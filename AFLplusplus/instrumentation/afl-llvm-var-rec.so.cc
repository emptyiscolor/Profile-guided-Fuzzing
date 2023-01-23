/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>,
              Adrian Herrera <adrian.herrera@anu.edu.au>,
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   NGRAM previous location coverage comes from Adrian Herrera.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_VAR_REC

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef AFL_LLVM_VAR_REC
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#endif

#include <fstream>
#include <list>
#include <string>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/Pass.h"
#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#else
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#if LLVM_VERSION_MAJOR >= 14 /* how about stable interfaces? */
#include "llvm/Passes/OptimizationLevel.h"
#endif

#if LLVM_VERSION_MAJOR >= 4 ||                                                 \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/CFG.h"
#include "llvm/IR/DebugInfo.h"
#else
#include "llvm/DebugInfo.h"
#include "llvm/Support/CFG.h"
#endif

#include "llvm/IR/IRBuilder.h"

#include "afl-llvm-common.h"
#include "llvm-alternative-coverage.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
class AFLVarRecovery : public PassInfoMixin<AFLVarRecovery> {

public:
  AFLVarRecovery() {

#else
class AFLVarRecovery : public ModulePass {

public:
  static char ID;
  AFLVarRecovery() : ModulePass(ID) {

#endif

    initInstrumentList();
  }

#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif
  static void addAttr(Module &M, bool is_constructor);

#ifdef AFL_LLVM_VAR_REC
  std::unordered_set<std::string> blacklistFuncs = {
      "exit_main", "skiplongjmp", "__afl_persistent_loop", "__afl_infinite"};
  std::unordered_set<std::string> blacklistVars = {"llvm.used", "snapshot_env",
                                                   "__afl_infinite"};
  std::map<GlobalVariable *, GlobalVariable *> staticGVMap;
  bool filter(std::unordered_set<std::string> targetSet, std::string target);
  bool processStore(Instruction *I,
                    std::unordered_set<GlobalVariable *> &globalSet);
  bool processGep(Instruction *I,
                  std::unordered_set<GlobalVariable *> &globalSet);
  bool processGEPOperator(GEPOperator *op,
                          std::unordered_set<GlobalVariable *> &globalSet);
  bool processBitcast(Instruction *I,
                      std::unordered_set<GlobalVariable *> &globalSet);
  bool processCallInvokeInst(Instruction *I,
                             std::unordered_set<GlobalVariable *> &globalSet);

  bool processOperands(Instruction *I,
                       std::unordered_set<GlobalVariable *> &globalSet);

  bool processGlobalSet(Module &M, IRBuilder<> IRB,
                        std::unordered_set<GlobalVariable *> globalSet);
  bool processNonStaticGV(Module &M, IRBuilder<> IRB, GlobalVariable *gv,
                          CallInst *call);
  bool processStaticGV(Module &M, IRBuilder<> IRB, GlobalVariable *gv,
                       CallInst *call);
  bool recoverGlobalSet(Module &M,
                        std::unordered_set<GlobalVariable *> globalSet);
#endif

protected:
  uint32_t ngram_size = 0;
  uint32_t ctx_k = 0;
  uint32_t map_size = MAP_SIZE;
  uint32_t function_minimum_size = 1;
  const char *ctx_str = NULL, *caller_str = NULL, *skip_nozero = NULL;
  const char *use_threadsafe_counters = nullptr;
};

} // namespace

static void filterGloablSet(std::unordered_set<GlobalVariable *> &globalSet) {

  for (auto it = globalSet.begin(); it != globalSet.end();) {
    // we may apply other conditions as well
    if ((*it)->isConstant())
      globalSet.erase(it++);
    else
      ++it;
  }
}

void AFLVarRecovery::addAttr(Module &M, bool is_constructor) {

  GlobalVariable *GV;
  if (is_constructor)
    GV = M.getGlobalVariable("llvm.global_ctors");
  else
    GV = M.getGlobalVariable("llvm.global_dtors");

  if (GV) {
    ConstantArray *Init = cast<ConstantArray>(GV->getInitializer());
    for (User::op_iterator OI = Init->op_begin(), OE = Init->op_end(); OI != OE;
         ++OI) {
      Value *Op = *OI;
      Function *F = dyn_cast<Function>(cast<ConstantStruct>(Op)->getOperand(1));
      if (!F)
        continue;
      if (F->isDeclaration())
        continue;
      if (is_constructor)
        F->addFnAttr("constructor");
      else
        F->addFnAttr("destructor");
    }
  }
}

#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "AFLVarRecovery", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if 1
#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(AFLVarRecovery());
                });

/* TODO LTO registration */
#else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {
              if (Name == "AFLVarRecovery") {

                MPM.addPass(AFLVarRecovery());
                return true;

              } else {

                return false;
              }
            });

#endif
          }};
}

#else

char AFLVarRecovery::ID = 0;
#endif

#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
PreservedAnalyses AFLVarRecovery::run(Module &M, ModuleAnalysisManager &MAM) {

#else
bool AFLVarRecovery::runOnModule(Module &M) {

#endif
  std::string resLine;

  LLVMContext &C = M.getContext();

#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
  auto PA = PreservedAnalyses::all();
#endif

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG"))
    debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST
              " by <lszekeres@google.com> and <adrian.herrera@anu.edu.au>\n");

  } else
    be_quiet = 1;
#ifdef AFL_LLVM_VAR_REC
  std::unordered_set<GlobalVariable *> globalFullSet;
#endif

#ifdef AFL_LLVM_VAR_REC_ALL
  // keep track of all global variables in the current module
  for (Module::global_iterator GV = M.global_begin(), GE = M.global_end();
       GV != GE; ++GV) {
    if (filter(blacklistVars, GV->getName().str()))
      continue;
    std::unordered_set<GlobalVariable *> allglobalSet;
    allglobalSet.insert(&*GV);
    filterGloablSet(allglobalSet);
    globalFullSet.insert(&*GV);
  }
#endif

  for (auto &F : M) {
#ifdef AFL_LLVM_VAR_REC
    if (F.hasFnAttribute("constructor") || F.hasFnAttribute("destructor") ||
        F.hasFnAttribute("noinst")) {
      SAYF("afl-llvm-pass: Con(De)structor: %s\n", F.getName().str().c_str());
      continue;
    }

    if (filter(blacklistFuncs, F.getName().str())) {
      SAYF(cCYA "afl-llvm-pass: Skip function: %s\n" cBRI cRST,
           F.getName().str().c_str());
      continue;
    }
#endif
    for (auto &BB : F) {
#ifdef AFL_LLVM_VAR_REC
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      /* Global values in current BB */
      std::unordered_set<GlobalVariable *> globalSet;

      for (auto &II : BB) {

        Instruction *I = &II;

        switch (I->getOpcode()) {

        case Instruction::Store:
          processStore(I, globalSet);
          processOperands(I, globalSet);
          break;

        case Instruction::GetElementPtr:
          processGep(I, globalSet);
          processOperands(I, globalSet);
          break;

        case Instruction::Call:
        case Instruction::Invoke:
          if (isa<DbgInfoIntrinsic>(I))
            break;

          processCallInvokeInst(I, globalSet);
          processOperands(I, globalSet);
          break;

        case Instruction::BitCast:
        case Instruction::PHI:
        case Instruction::Select:
        case Instruction::Ret:
        case Instruction::PtrToInt:
        case Instruction::InsertValue:
        case Instruction::InsertElement:
          processOperands(I, globalSet);
          break;

        default:
          break;
        }
      }

      filterGloablSet(globalSet);

      if (getenv("AFL_VAR_TRACE")) {
        processGlobalSet(M, IRB, globalSet);
      } else {
        if (getenv("AFL_VAR_SNAPSHOT"))
          globalFullSet.insert(globalSet.begin(), globalSet.end());
      }
#endif
    }
  }
#ifdef AFL_LLVM_VAR_REC
  if (getenv("AFL_VAR_SNAPSHOT"))
    recoverGlobalSet(M, globalFullSet);
#endif

#if LLVM_VERSION_MAJOR >= 11 /* use new pass manager */
  return PA;
#else
  return true;
#endif
}

#ifdef AFL_LLVM_VAR_REC
bool AFLVarRecovery::filter(std::unordered_set<std::string> targetset,
                            std::string target) {
  if (targetset.find(target) != targetset.end())
    return true;
  else
    return false;
}

bool AFLVarRecovery::processStore(
    Instruction *I, std::unordered_set<GlobalVariable *> &globalSet) {

  if (StoreInst *SI = dyn_cast<StoreInst>(I)) {

    Value *AddrOp = SI->getPointerOperand();

    // direct store to global variable
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(AddrOp))
      globalSet.insert(GV);
  }
  return true;
}

bool AFLVarRecovery::processBitcast(
    Instruction *I, std::unordered_set<GlobalVariable *> &globalSet) {

  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(I->getOperand(0))) {
    for (auto U : I->users()) {
      // maybe there are other cases
      if (dyn_cast<GetElementPtrInst>(U)) {
        globalSet.insert(GV);
        return true;
      }
    }
  }

  return true;
}

bool AFLVarRecovery::processGep(
    Instruction *I, std::unordered_set<GlobalVariable *> &globalSet) {

  Value *AddrOp = I->getOperand(0);

  // load address of global variable
  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(AddrOp)) {
    globalSet.insert(GV);
  }

  return true;
}

bool AFLVarRecovery::processCallInvokeInst(
    Instruction *I, std::unordered_set<GlobalVariable *> &globalSet) {
  if (CallInst *CI = dyn_cast<CallInst>(I)) {

    if (Function *fn = CI->getCalledFunction()) {

      for (auto arg = fn->arg_begin(); arg != fn->arg_end(); ++arg) {

        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(arg))
          globalSet.insert(GV);

        if (dyn_cast<GetElementPtrInst>(arg))
          processGep(dyn_cast<Instruction>(arg), globalSet);

        if (dyn_cast<GEPOperator>(arg))
          processGEPOperator(dyn_cast<GEPOperator>(arg), globalSet);
      }
    }
  }
  if (InvokeInst *II = dyn_cast<InvokeInst>(I)) {

    if (Function *fn = II->getCalledFunction()) {

      for (auto arg = fn->arg_begin(); arg != fn->arg_end(); ++arg) {

        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(arg))
          globalSet.insert(GV);

        if (dyn_cast<GetElementPtrInst>(arg))
          processGep(dyn_cast<Instruction>(arg), globalSet);

        if (dyn_cast<GEPOperator>(arg))
          processGEPOperator(dyn_cast<GEPOperator>(arg), globalSet);
      }
    }
  }
  return true;
}

bool AFLVarRecovery::processGEPOperator(
    GEPOperator *op, std::unordered_set<GlobalVariable *> &globalSet) {

  Value *AddrOp = op->getPointerOperand();

  // load address of global variable
  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(AddrOp)) {
    globalSet.insert(GV);
  }

  return true;
}

bool AFLVarRecovery::processOperands(
    Instruction *I, std::unordered_set<GlobalVariable *> &globalSet) {

  for (int i = 0; i < I->getNumOperands(); i++) {
    Value *op = I->getOperand(i);

    if (dyn_cast<GetElementPtrInst>(op))
      processGep(dyn_cast<Instruction>(op), globalSet);

    if (dyn_cast<GEPOperator>(op))
      processGEPOperator(dyn_cast<GEPOperator>(op), globalSet);
  }
  return true;
}

bool AFLVarRecovery::processNonStaticGV(Module &M, IRBuilder<> IRB,
                                        GlobalVariable *global,
                                        CallInst *fileHandle) {

  auto *name = IRB.CreateGlobalStringPtr(global->getName());

  auto *fprintfType = FunctionType::get(
      IRB.getInt32Ty(), SmallVector<Type *, 1>{IRB.getInt8PtrTy()}, true);

  auto fprintfFunc = M.getOrInsertFunction("fprintf", fprintfType);

  IRB.CreateCall(fprintfFunc,
                 SmallVector<Value *, 3>{
                     fileHandle, IRB.CreateGlobalStringPtr("G:%s\n"), name});

  return true;
}

static void sanitize_string(std::string &string) {
  std::replace(string.begin(), string.end(), '.', 'd');
  std::replace(string.begin(), string.end(), '/', 's');
  std::replace(string.begin(), string.end(), '-', 'm');
  std::replace(string.begin(), string.end(), '\\', 't');
}

bool AFLVarRecovery::processStaticGV(Module &M, IRBuilder<> IRB,
                                     GlobalVariable *global,
                                     CallInst *fileHandle) {

  DataLayout dataLayout(&M);

  std::string moduleName = M.getName().str();
  sanitize_string(moduleName);

  auto *ptrname =
      IRB.CreateGlobalStringPtr(global->getName().str() + "_ptr_" + moduleName);

  auto *name = IRB.CreateGlobalStringPtr(global->getName());

  auto *size = ConstantInt::get(
      IRB.getInt64Ty(),
      dataLayout.getTypeSizeInBits(global->getValueType()).getFixedSize() / 8);

  auto *fprintfType = FunctionType::get(
      IRB.getInt32Ty(), SmallVector<Type *, 1>{IRB.getInt8PtrTy()}, true);

  auto fprintfFunc = M.getOrInsertFunction("fprintf", fprintfType);

  IRB.CreateCall(fprintfFunc,
                 SmallVector<Value *, 5>{
                     fileHandle, IRB.CreateGlobalStringPtr("S:%s:%s:%d\n"),
                     ptrname, name, size});

  return true;
}

bool AFLVarRecovery::processGlobalSet(
    Module &M, IRBuilder<> IRB,
    std::unordered_set<GlobalVariable *> globalSet) {

  if (globalSet.size() == 0)
    return true;

  // open a log file
  std::string dumpFilename = "/tmp/.fs_globals.txt";
  auto *fopenType = FunctionType::get(
      IRB.getInt8PtrTy(),
      SmallVector<Type *, 2>{IRB.getInt8PtrTy(), IRB.getInt8PtrTy()}, false);

  auto fopenFunc = M.getOrInsertFunction("fopen", fopenType);
  auto *fileHandle = IRB.CreateCall(
      fopenFunc,
      SmallVector<Value *, 2>{IRB.CreateGlobalStringPtr(dumpFilename),
                              IRB.CreateGlobalStringPtr("a")});

  // instrument code to log global variables
  for (auto *global : globalSet) {
    if (global->getLinkage() == GlobalValue::ExternalLinkage) {
      processNonStaticGV(M, IRB, global, fileHandle);
    } else {
      processStaticGV(M, IRB, global, fileHandle);
    }
  }

  /* fclose(fileHandle); */
  auto *fcloseType = FunctionType::get(
      IRB.getInt8PtrTy(), SmallVector<Type *, 1>{IRB.getInt8PtrTy()}, false);

  auto fcloseFunc = M.getOrInsertFunction("fclose", fcloseType);
  IRB.CreateCall(fcloseFunc, SmallVector<Value *, 1>{fileHandle});

  return true;
}

bool AFLVarRecovery::recoverGlobalSet(
    Module &M, std::unordered_set<GlobalVariable *> globalSet) {

  if (globalSet.size() == 0)
    return true;

  LLVMContext &C = M.getContext();
  // void type
  Type *voidTy = Type::getVoidTy(C);

  // 64 bit integer
  // IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  // PointerType *PointerCharTy = PointerType::get(Int8Ty, 0);

  bool isVarArg = false;

  std::string moduleName = M.getName().str();
  std::string parentPath = std::filesystem::current_path().filename().string();
  std::string fullmoduleName = parentPath + M.getName().str();
  sanitize_string(fullmoduleName);
  sanitize_string(moduleName);

  std::string funcName = fullmoduleName + "_var_snapshot";

  FunctionType *saveFunctionCallType = FunctionType::get(voidTy, isVarArg);

  Function *saveFunc = Function::Create(saveFunctionCallType,
                                        Function::ExternalLinkage, funcName, M);

  saveFunc->addFnAttr(llvm::Attribute::AlwaysInline);

  BasicBlock *entry = BasicBlock::Create(C, "entry", saveFunc);
  IRBuilder<> fnBuilder(entry);

  // instrument code to log global variables
  for (auto *global : globalSet) {

    if (global->getLinkage() != GlobalValue::ExternalLinkage) {

      GlobalVariable *globalPtr =
          new GlobalVariable(M, PointerType::get(global->getValueType(), 0),
                             false, GlobalValue::ExternalLinkage, global,
                             global->getName().str() + "_ptr_" + moduleName);
      globalPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      if (globalPtr)
        fnBuilder.CreateStore(global, globalPtr);
    }
  }

  fnBuilder.CreateRetVoid();

  appendToGlobalCtors(M, saveFunc, 2, nullptr);

  return true;
}

#endif

#if LLVM_VERSION_MAJOR < 11 /* use old pass manager */
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLVarRecovery());
}

static RegisterStandardPasses
    RegisterAFLPass(PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses
    RegisterAFLPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                     registerAFLPass);
#endif
