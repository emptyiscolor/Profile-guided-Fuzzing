#!/bin/bash

# eg.
# ./eval-AFL-queue.sh -p id -s /home/ubuntu/code/test/binutils-2.38/binutils/findings_o1/queue -o /tmp/strace-stat "objdump -s"
# DIFF:
# ./eval-AFL-queue.sh --evaluate -p id -s /home/ubuntu/code/test/binutils-2.38/binutils/findings_o8/queue -o /tmp/diff-stat "/home/ubuntu/code/test/binutils-2.38/binutils/objdump -s"

PATTERN_MAIN='write(199'
PATTERN_SYSCALL_NAME='openat'
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--prefix)
      PREFIX="$2"
      shift # past argument
      shift # past value
      ;;
    -o|--output)
      OUTPUT="$2"
      shift # past argument
      shift # past value
      ;;
    -s|--searchpath)
      SEARCHPATH="$2"
      shift # past argument
      shift # past value
      ;;
    -n|--syscallname)
      PATTERN_SYSCALL_NAME="$2"
      shift # past argument
      shift # past value
      ;;
    --evaluate)
      EVALUATE=YES
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

echo "FILE PREFIX     = ${PREFIX}"
echo "OUTPUT PATH     = ${OUTPUT}"
echo "SEARCH PATH     = ${SEARCHPATH}"
echo "EVALUATE         = ${EVALUATE}"

if [ -z "$OUTPUT" ]; then
  echo "No output path specified" && exit 1;
fi

if [ ! -d $OUTPUT ]; then
  mkdir -p "$OUTPUT";
fi

if [ -z "$1" ]
  then
    echo "No target supplied"
    exit 1
fi

if [ -z "$EVALUATE" ]
then
  echo "\$EVALUATE is not set. Use strace for collection"
else
  echo "Comparing the output of the program..."
  for filename in "${SEARCHPATH}/${PREFIX}"*; do
    diff <($1 "$filename"  2>&1) <(FS_AFL_SHM_ID=4919 TESTFILE=$filename $1 "$filename"   2>&1) >/dev/null  2>&1 ; ec=$?
    case $ec in
      1) echo $filename >> "${OUTPUT}/diff.txt"
              ;;
      0) printf "$filename \tsame output\n"
              ;;
      *) echo $filename >> "${OUTPUT}/diff.txt"
              ;;
    esac
    # clear shared memory
    ipcs -m | grep `whoami` | awk '{ print $2 }' | xargs -n1 ipcrm -m
      
  done

  exit $?
fi

printf "strace on $1\n\tfor each file in ${SEARCHPATH}\n\twith prefix: \'${PREFIX}\' \n"

for filename in "${SEARCHPATH}/${PREFIX}"*; do
  TRACE_OUT_FILE_BASE=$(basename "${filename}")
  TRACE_OUT="${OUTPUT}/${TRACE_OUT_FILE_BASE}.strace.txt"
  strace $1 "$filename" 2>&1 >/dev/null |\
    sed -n "/$PATTERN_MAIN/,\$p" |\
    sed '1d' |\
    grep -v exited  > $TRACE_OUT

    if [ -s $TRACE_OUT ]; then
      if [ "$PATTERN_SYSCALL_NAME" == "openat" ]; then
        grep "$PATTERN_SYSCALL_NAME" $TRACE_OUT | grep "ENOENT" |\
          cut -d',' -f2 | tr -d ' ' | sed 's/[""]//g'  > "${OUTPUT}/${TRACE_OUT_FILE_BASE}.open.ENOENT.txt"
        grep "$PATTERN_SYSCALL_NAME" $TRACE_OUT | grep -v "ENOENT" | grep -v "$filename" |\
          cut -d',' -f2 | sed 's/[""]//g' | tr -d ' ' > "${OUTPUT}/${TRACE_OUT_FILE_BASE}.open.EXIST.txt"
      elif [ "$PATTERN_SYSCALL_NAME" == 'open' ]; then
        grep 'open(' $TRACE_OUT | grep "ENOENT" |\
          grep -oP '"\K[^"\047]+(?=["\047])'  > "${OUTPUT}/${TRACE_OUT_FILE_BASE}.open.ENOENT.txt"
        grep 'open(' $TRACE_OUT | grep -v "ENOENT" | grep -v "$filename" |\
          cut -d',' -f1 | sed 's/[""]//g' | sed -e 's/^open(//' | tr -d ' ' > "${OUTPUT}/${TRACE_OUT_FILE_BASE}.open.EXIST.txt"
      elif [ "$PATTERN_SYSCALL_NAME" == 'mmap' ]; then
        grep "$PATTERN_SYSCALL_NAME" $TRACE_OUT |\
          grep 'mmap(NULL' | grep -vE 'MAP_FIXED|MAP_STACK' |\
          grep 'MAP_PRIVATE|MAP_ANONYMOUS, \-1, 0)' | cut -d',' -f2 | tr -d ' ' |\
            awk '{s+=$1} END {print s}' > "${OUTPUT}/${TRACE_OUT_FILE_BASE}.PRIVATE_ANONYMOUS.mmap.txt"
      fi
    fi
done

if [ "$PATTERN_SYSCALL_NAME" == 'mmap' ]; then
  cat ${OUTPUT}/*.PRIVATE_ANONYMOUS.mmap.txt | sort -nr | head -n1 > ${OUTPUT}/PRIVATE.mmap.txt
else
  cat ${OUTPUT}/*.open.ENOENT.txt | sort -u > ${OUTPUT}/open.ENOENT.txt
  cat ${OUTPUT}/*.open.EXIST.txt | sort -u | xargs -I % find %  -mtime +1 > ${OUTPUT}/open.EXIST.txt
fi

rm -f ${OUTPUT}/$PREFIX*
rm -f ${OUTPUT}/.open.ENOENT.txt

echo Done.
