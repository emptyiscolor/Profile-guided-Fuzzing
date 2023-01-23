/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/DebugLoc.h"

// #define VAR_REC

#ifdef VAR_REC

#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <filesystem>
#include "llvm/Support/raw_ostream.h"

#endif



// #define TEST_FS

using namespace llvm;

namespace
{

    class AFLCoverage : public ModulePass
    {

    public:
        static char ID;
        AFLCoverage() : ModulePass(ID) {}

        bool runOnModule(Module &M) override;

        // StringRef getPassName() const override {
        //  return "American Fuzzy Lop Instrumentation";
        // }

#ifdef VAR_REC
        std::unordered_set<std::string> blacklistFuncs = {"exit_main", "skiplongjmp", "__afl_persistent_loop", "__afl_infinite"};
        std::map<GlobalVariable *, GlobalVariable *> staticGVMap;
        bool filter(std::unordered_set<std::string> targetSet, std::string target);
        bool processStore(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet);
        bool processGep(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet);
        bool processGEPOperator(GEPOperator *op, std::unordered_set<GlobalVariable *> &globalSet);
        bool processBitcast(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet);

        bool processOperands(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet);

        bool processGlobalSet(Module &M, IRBuilder<> IRB, std::unordered_set<GlobalVariable *> globalSet);
        bool processNonStaticGV(Module &M, IRBuilder<> IRB, GlobalVariable *gv, CallInst *call);
        bool processStaticGV(Module &M, IRBuilder<> IRB, GlobalVariable *gv, CallInst *call);
        bool recoverGlobalSet(Module &M, std::unordered_set<GlobalVariable *> globalSet);
#endif
    };

}

char AFLCoverage::ID = 0;

#if defined(VAR_REC) || defined(TEST_FS)
static void sanitize_string(std::string &string)
{
    std::replace(string.begin(), string.end(), '.', 'd');
    std::replace(string.begin(), string.end(), '/', 's');
    std::replace(string.begin(), string.end(), '-', 'm');
    std::replace(string.begin(), string.end(), '\\', 't');
}

#endif


#ifdef VAR_REC

bool AFLCoverage::filter(std::unordered_set<std::string> targetset, std::string target)
{
    if (targetset.find(target) != targetset.end())
        return true;
    else
        return false;
}

bool AFLCoverage::processStore(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet)
{

    if (StoreInst *SI = dyn_cast<StoreInst>(I))
    {

        Value *AddrOp = SI->getPointerOperand();

        // direct store to global variable
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(AddrOp))
            globalSet.insert(GV);
    }
    return true;
}

bool AFLCoverage::processBitcast(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet)
{

    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(I->getOperand(0)))
    {
        for (auto U : I->users())
        {
            // maybe there are other cases
            if (dyn_cast<GetElementPtrInst>(U))
            {
                globalSet.insert(GV);
                return true;
            }
        }
    }

    return true;
}

bool AFLCoverage::processGep(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet)
{

    Value *AddrOp = I->getOperand(0);

    // load address of global variable
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(AddrOp))
    {
        globalSet.insert(GV);
    }

    return true;
}

bool AFLCoverage::processGEPOperator(GEPOperator *op, std::unordered_set<GlobalVariable *> &globalSet)
{

    Value *AddrOp = op->getPointerOperand();

    // load address of global variable
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(AddrOp))
    {
        globalSet.insert(GV);
    }

    return true;
}

bool AFLCoverage::processOperands(Instruction *I, std::unordered_set<GlobalVariable *> &globalSet)
{

    for (int i = 0; i < I->getNumOperands(); i++)
    {
        Value *op = I->getOperand(i);

        if (dyn_cast<GetElementPtrInst>(op))
            processGep(dyn_cast<Instruction>(op), globalSet);

        if (dyn_cast<GEPOperator>(op))
            processGEPOperator(dyn_cast<GEPOperator>(op), globalSet);
    }
    return true;
}

bool AFLCoverage::processNonStaticGV(Module &M, IRBuilder<> IRB, GlobalVariable *global, CallInst *fileHandle)
{

    auto *name = IRB.CreateGlobalStringPtr(global->getName());

    auto *fprintfType = FunctionType::get(
        IRB.getInt32Ty(),
        SmallVector<Type *, 1>{IRB.getInt8PtrTy()},
        true);

    auto fprintfFunc = M.getOrInsertFunction("fprintf", fprintfType);

    IRB.CreateCall(fprintfFunc, SmallVector<Value *, 3>{
                                    fileHandle,
                                    IRB.CreateGlobalStringPtr("G:%s\n"),
                                    name});

    return true;
}

static void filterGloablSet(std::unordered_set<GlobalVariable *> &globalSet)
{

    for (auto it = globalSet.begin(); it != globalSet.end();)
    {
        // we may apply other conditions as well
        if ((*it)->isConstant())
            globalSet.erase(it++);
        else
            ++it;
    }
}

bool AFLCoverage::processStaticGV(Module &M, IRBuilder<> IRB, GlobalVariable *global, CallInst *fileHandle)
{

    DataLayout dataLayout(&M);

    std::string moduleName = M.getName().str();
    sanitize_string(moduleName);

    auto *ptrname = IRB.CreateGlobalStringPtr(global->getName().str() + "_ptr_" + moduleName);

    auto *name = IRB.CreateGlobalStringPtr(global->getName());

    auto *size = ConstantInt::get(
        IRB.getInt64Ty(),
        dataLayout.getTypeSizeInBits(global->getValueType()).getFixedSize() / 8);

    auto *fprintfType = FunctionType::get(
        IRB.getInt32Ty(),
        SmallVector<Type *, 1>{IRB.getInt8PtrTy()},
        true);

    auto fprintfFunc = M.getOrInsertFunction("fprintf", fprintfType);

    IRB.CreateCall(fprintfFunc, SmallVector<Value *, 5>{
                                    fileHandle,
                                    IRB.CreateGlobalStringPtr("S:%s:%s:%d\n"),
                                    ptrname, name, size});

    return true;
}

bool AFLCoverage::processGlobalSet(Module &M, IRBuilder<> IRB, std::unordered_set<GlobalVariable *> globalSet)
{

    if (globalSet.size() == 0)
        return true;

    // open a log file
    std::string dumpFilename = "/tmp/.fs_globals.txt";
    auto *fopenType = FunctionType::get(
        IRB.getInt8PtrTy(),
        SmallVector<Type *, 2>{IRB.getInt8PtrTy(), IRB.getInt8PtrTy()},
        false);

    auto fopenFunc = M.getOrInsertFunction("fopen", fopenType);
    auto *fileHandle = IRB.CreateCall(fopenFunc, SmallVector<Value *, 2>{
                                                     IRB.CreateGlobalStringPtr(dumpFilename),
                                                     IRB.CreateGlobalStringPtr("a")});

    // instrument code to log global variables
    for (auto *global : globalSet)
    {
        if (global->getLinkage() == GlobalValue::ExternalLinkage)
        {
            processNonStaticGV(M, IRB, global, fileHandle);
        }
        else
        {
            processStaticGV(M, IRB, global, fileHandle);
        }
    }

    /* fclose(fileHandle); */
    auto *fcloseType = FunctionType::get(
        IRB.getInt8PtrTy(),
        SmallVector<Type *, 1>{IRB.getInt8PtrTy()},
        false);

    auto fcloseFunc = M.getOrInsertFunction("fclose", fcloseType);
    IRB.CreateCall(fcloseFunc, SmallVector<Value *, 1>{fileHandle});

    return true;
}

bool AFLCoverage::recoverGlobalSet(Module &M, std::unordered_set<GlobalVariable *> globalSet)
{

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
    sanitize_string(moduleName);

    std::string funcName = moduleName + "_var_snapshot";

    FunctionType *saveFunctionCallType = FunctionType::get(voidTy, isVarArg);

    Function *saveFunc = Function::Create(saveFunctionCallType, Function::ExternalLinkage, funcName, M);

    saveFunc->addFnAttr(llvm::Attribute::AlwaysInline);

    BasicBlock *entry = BasicBlock::Create(C, "entry", saveFunc);
    IRBuilder<> fnBuilder(entry);

    // instrument code to log global variables
    for (auto *global : globalSet)
    {

        if (global->getLinkage() != GlobalValue::ExternalLinkage)
        {

            GlobalVariable *globalPtr = new GlobalVariable(M, PointerType::get(global->getValueType(), 0), false, GlobalValue::ExternalLinkage, global, global->getName().str() + "_ptr_" + moduleName);
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


bool AFLCoverage::runOnModule(Module &M)
{

    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    /* Show a banner */

    char be_quiet = 0;

    if (isatty(2) && !getenv("AFL_QUIET"))
    {

        SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");
    }
    else
        be_quiet = 1;

    /* Decide instrumentation ratio */

    char *inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;

    if (inst_ratio_str)
    {

        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
            FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
    }

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    /* Instrument all the things! */

    int inst_blocks = 0;

#ifdef VAR_REC
    // keep track of all global variables in the current module
    std::unordered_set<GlobalVariable *> globalFullSet;
#endif

/* a utility pass to help test the VFS; do not use it */
#ifdef TEST_FS

    static unsigned bblNum = 0;

    // open a log file
    std::string dumpFilename = "/tmp/.fs_test.txt";

    for (auto &F : M)
    {
	    for (auto &BB : F){
		    BasicBlock::iterator IP = BB.getFirstInsertionPt();
		    IRBuilder<> IRB(&(*IP));


		    const llvm::DebugLoc &debugInfo = (&(*IP))->getDebugLoc();

		    //std::string directory = debugInfo.getDirectory();

		    //std::string filePath = debugInfo.getFilename();
		   

		    int line = 0; 
		    
		    if(debugInfo)
			    line = debugInfo.getLine();


		    auto *fopenType = FunctionType::get(
				    IRB.getInt8PtrTy(),
				    SmallVector<Type *, 2>{IRB.getInt8PtrTy(), IRB.getInt8PtrTy()},
				    false);


		    auto fopenFunc = M.getOrInsertFunction("fopen", fopenType);
		    auto *fileHandle = IRB.CreateCall(fopenFunc, SmallVector<Value *, 2>{
				    IRB.CreateGlobalStringPtr(dumpFilename),
				    IRB.CreateGlobalStringPtr("a")});

		    auto *fprintfType = FunctionType::get(
				    IRB.getInt32Ty(),
				    SmallVector<Type *, 1>{IRB.getInt8PtrTy()},
				    true);


		    std::string moduleName = M.getName().str();

		    auto fprintfFunc = M.getOrInsertFunction("fprintf", fprintfType);

		    IRB.CreateCall(fprintfFunc, SmallVector<Value *, 2>{
				    fileHandle,
				    IRB.CreateGlobalStringPtr("\n@@" + moduleName + "@" +  std::to_string(line) + "@" + F.getName().str() + "@@\n")});

		    auto *fcloseType = FunctionType::get(
				    IRB.getInt8PtrTy(),
				    SmallVector<Type *, 1>{IRB.getInt8PtrTy()},
				    false);

		    auto fcloseFunc = M.getOrInsertFunction("fclose", fcloseType);
		    IRB.CreateCall(fcloseFunc, SmallVector<Value *, 1>{fileHandle});




	    }




    }

    return true;
#endif

    for (auto &F : M)
    {

#ifdef VAR_REC

        if (F.hasFnAttribute("constructor") || F.hasFnAttribute("destructor") || F.hasFnAttribute("noinst"))
        {
            SAYF("afl-llvm-pass: Con(De)structor: %s\n", F.getName().str().c_str());
            continue;
        }

        if (filter(blacklistFuncs, F.getName().str()))
        {
            SAYF(cCYA "afl-llvm-pass: Skip function: %s\n" cBRI cRST, F.getName().str().c_str());
            continue;
        }
#endif

        for (auto &BB : F)
        {
            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));

#ifdef VAR_REC
            /* Global values in current BB */
            std::unordered_set<GlobalVariable *> globalSet;

            for (auto &II : BB)
            {

                Instruction *I = &II;

                switch (I->getOpcode())
                {

                case Instruction::Store:
                    processStore(I, globalSet);
                    processOperands(I, globalSet);
                    break;

                case Instruction::BitCast:
                    processBitcast(I, globalSet);
                    break;

                case Instruction::GetElementPtr:
                    processGep(I, globalSet);
                    processOperands(I, globalSet);
                    break;

                case Instruction::Call:
                case Instruction::PHI:
                case Instruction::Select:
                    processOperands(I, globalSet);
                    break;

                default:
                    break;
                }
            }

            filterGloablSet(globalSet);

            if (getenv("AFL_VAR_TRACE"))
            {
                processGlobalSet(M, IRB, globalSet);
            }
            else
            {
                if (getenv("AFL_VAR_SNAPSHOT"))
                    globalFullSet.insert(globalSet.begin(), globalSet.end());
            }
#endif

            if (AFL_R(100) >= inst_ratio)
                continue;

            /* Make up cur_loc */

            unsigned int cur_loc = AFL_R(MAP_SIZE);

            ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

            /* Load prev_loc */

            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

            /* Load SHM pointer */

            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *MapPtrIdx =
                IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

            /* Update bitmap */

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(Incr, MapPtrIdx)
                ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            /* Set prev_loc to cur_loc >> 1 */

            StoreInst *Store =
                IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
            Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            inst_blocks++;
        }
    }

#ifdef VAR_REC
    if (getenv("AFL_VAR_SNAPSHOT"))
        recoverGlobalSet(M, globalFullSet);
#endif

    /* Say something nice. */

    if (!be_quiet)
    {

        if (!inst_blocks)
            WARNF("No instrumentation targets found.");
        else
            OKF("Instrumented %u locations (%s mode, ratio %u%%).",
                inst_blocks, getenv("AFL_HARDEN") ? "hardened" : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ? "ASAN/MSAN" : "non-hardened"), inst_ratio);
    }

    return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM)
{

    PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
