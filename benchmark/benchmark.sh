#!/bin/bash

# Generate time and memory usage profiles for basic library operations
#
# pip install psutil [memory_profiler [matplotlib]]

HERE=`dirname $0`
BENCHMARK_PY="$HERE/benchmark.py"

if hash mprof 2>/dev/null; then
  MPROF_CLEAN="mprof clean"
  MPROF_RUN="mprof run"

  if python -c 'import matplotlib' 2>/dev/null; then
    MPROF_PLOT="mprof plot"
  fi
fi

n=1000;

echo "Starting tests, n=$n"

$MPROF_CLEAN

# identify the runtime environment, Python version, etc
#
python $BENCHMARK_PY --environment

# AES key generation
echo 'AES key generation'
time python $BENCHMARK_PY --aes-keys --count $n
$MPROF_RUN python $BENCHMARK_PY --aes-keys --count $n
$MPROF_PLOT

# Symmetric encrytion/decryption
echo 'Symmetric encrytion/decryption'
for size in 10 100 1000 10000 100000 1000000; do
  echo '  size=' $size
  time python $BENCHMARK_PY --symmetric --data-size $size --count $n
  $MPROF_RUN python $BENCHMARK_PY --symmetric --data-size $size --count $n
  $MPROF_PLOT
done

# ECDSA key generation
echo 'ECDSA key generation'
time python $BENCHMARK_PY --ecdsa-key --count $n
$MPROF_RUN python $BENCHMARK_PY --ecdsa-key --count $n

# ECDSA signing/verifying
echo 'ECDSA signing/verifying'
for size in 10 100 1000 10000 100000 1000000; do
  echo '  size=' $size
  time python $BENCHMARK_PY --asymmetric --data-size $size --count $n
  $MPROF_RUN python $BENCHMARK_PY --asymmetric --data-size $size --count $n
  $MPROF_PLOT
done

# JWT creation/verification
echo 'JWT creation/verification'
for size in 10 100 1000 10000 100000 1000000; do
  echo '  size=' $size
  time python $BENCHMARK_PY --jwt --data-size $size --count $n
  $MPROF_RUN python $BENCHMARK_PY --jwt --data-size $size --count $n
  $MPROF_PLOT
done

echo 'Benchmarks complete'
