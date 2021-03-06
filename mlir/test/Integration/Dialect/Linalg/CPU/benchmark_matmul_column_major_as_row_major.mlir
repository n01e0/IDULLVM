// RUN: export M=24 && export K=64 && export N=192 && export ITERS=10 && \
// RUN: cat %s | sed 's@${M}@'"$M"'@g'| sed 's@${K}@'"$K"'@g' | sed 's@${N}@'"$N"'@g'| sed 's@${ITERS}@'"$ITERS"'@g'| \
// RUN: mlir-opt -test-linalg-codegen-strategy="anchor-func=matmul_column_major_as_row_major anchor-op=linalg.matmul_column_major register-tile-sizes=16,0,32 vectorize" | \
// RUN: mlir-opt -test-linalg-codegen-strategy="anchor-func=matmul_column_major_as_row_major anchor-op=linalg.matmul register-tile-sizes=12,32,16 vectorize" | \
// RUN: mlir-opt -test-linalg-codegen-strategy="anchor-op=linalg.fill register-tile-sizes=4,16 vectorize" | \

// TODO: linalg.copy vectorization in the presence of permutation map fails. Enable when addressed.
// R_UN: mlir-opt -test-linalg-codegen-strategy="anchor-op=linalg.copy register-tile-sizes=4,16 vectorize" | \

// RUN: mlir-opt -canonicalize -convert-vector-to-scf -lower-affine -convert-linalg-to-loops | \
// RUN: mlir-opt -canonicalize -convert-scf-to-std -convert-vector-to-llvm -convert-memref-to-llvm -convert-std-to-llvm | \
// RUN: mlir-cpu-runner -O3 -e main -entry-point-result=void \
// Activate to dump assembly
// R_UN:   -dump-object-file -object-filename=/tmp/a.o \
// RUN:   -shared-libs=%mlir_integration_test_dir/libmlir_runner_utils%shlibext \
// RUN:   -shared-libs=%mlir_integration_test_dir/libmlir_c_runner_utils%shlibext | \
// Use tee to both print to stderr and FileCheck
// RUN: tee -a /dev/stderr | FileCheck %s

!elem_type_a = type f32
!elem_type_b = type f32
!elem_type_c = type f32
!row_major_A = type memref<${M}x${K}x!elem_type_a>
!row_major_B = type memref<${K}x${N}x!elem_type_b>
!row_major_C = type memref<${M}x${N}x!elem_type_c>
!column_major_A = type memref<${K}x${M}x!elem_type_a>
!column_major_B = type memref<${N}x${K}x!elem_type_b>
!column_major_C = type memref<${N}x${M}x!elem_type_c>

func @matmul_column_major_as_row_major(
  %ca: !column_major_A, %cb: !column_major_B, %cc: !column_major_C,
   %a: !row_major_A,     %b: !row_major_B,     %c: !row_major_C)
// TODO: activate manually for now.
// attributes { passthrough = [["target-cpu", "skylake-avx512"], ["prefer-vector-width", "512"]]}
{
  linalg.copy(%ca, %a) {inputPermutation = affine_map<(i, j) -> (j, i)> } : !column_major_A, !row_major_A
  linalg.copy(%cb, %b) {inputPermutation = affine_map<(i, j) -> (j, i)> } : !column_major_B, !row_major_B
  linalg.matmul ins(%a, %b : !row_major_A, !row_major_B)
    outs(%c: !row_major_C)
  linalg.copy(%c, %cc) {inputPermutation = affine_map<(i, j) -> (j, i)> } : !row_major_C, !column_major_C
  return
}

func @print_perf(%iters: index, %total_time: f64) {
  %c2 = constant 2 : index
  %cM = constant ${M} : index
  %cN = constant ${N} : index
  %cK = constant ${K} : index

  %mn = muli %cM, %cN : index
  %mnk = muli %mn, %cK : index

  // 2*M*N*K.
  %flops_per_iter = muli %c2, %mnk : index
  %flops = muli %iters, %flops_per_iter : index
  %flops_i64 = index_cast %flops : index to i64
  %flops_f = sitofp %flops_i64 : i64 to f64
  %flops_per_s = divf %flops_f, %total_time : f64
  vector.print %flops_per_s : f64

  return
}

func @main() {
  %f0 = constant 0.0 : !elem_type_c
  %f1 = constant 1.0 : !elem_type_a

  %cA = memref.alloc() : !column_major_A
  %cB = memref.alloc() : !column_major_B
  %cC = memref.alloc() : !column_major_C

  linalg.fill(%f1, %cA) : !elem_type_a, !column_major_A
  linalg.fill(%f1, %cB) : !elem_type_b, !column_major_B
  linalg.fill(%f0, %cC) : !elem_type_c, !column_major_C

  %c0 = constant 0: index
  %c1 = constant 1: index
  %iters = constant ${ITERS}: index

  /// Run and dump performance for matmul_column_major as a row-major
  %A = memref.alloc() : !row_major_A
  %B = memref.alloc() : !row_major_B
  %C = memref.alloc() : !row_major_C
  %t_start_matmul_column_major_as_row_major = call @rtclock() : () -> f64
  scf.for %arg0 = %c0 to %iters step %c1 {
    // linalg.matmul writes %C in place, need to reset it to zero every time.
    // This is accounts for about 10-15% perf hit on small sizes.
    // Once linalg on tensors is ready, fusing fill at the register level will
    // be easy.
    linalg.fill(%f0, %C) : !elem_type_c, !row_major_C
    call @matmul_column_major_as_row_major(%cA, %cB, %cC, %A, %B, %C) :
      (!column_major_A, !column_major_B, !column_major_C,
       !row_major_A, !row_major_B, !row_major_C) -> ()
  }
  %t_end_matmul_column_major_as_row_major = call @rtclock() : () -> f64
  %tmatmul_column_major_as_row_major = subf %t_end_matmul_column_major_as_row_major, %t_start_matmul_column_major_as_row_major: f64
  call @print_perf(%iters, %tmatmul_column_major_as_row_major) : (index, f64) -> ()

  // CHECK: {{^0$}}
  %cC_ref = memref.alloc() : !column_major_C
  linalg.fill(%f0, %cC_ref) : !elem_type_c, !column_major_C
  linalg.matmul_column_major ins(%cA, %cB : !column_major_A, !column_major_B)
    outs(%cC_ref: !column_major_C)
  %act1 = memref.cast %cC : !column_major_C to memref<*xf32>
  %exp1 = memref.cast %cC_ref : !column_major_C to memref<*xf32>
  %errors1 = call @verifyMemRefF32(%act1, %exp1) : (memref<*xf32>, memref<*xf32>) -> i64
  vector.print %errors1 : i64
  memref.dealloc %cC_ref : !column_major_C

  // CHECK: {{^0$}}
  %C_ref = memref.alloc() : !row_major_C
  linalg.fill(%f0, %C_ref) : !elem_type_c, !row_major_C
  linalg.matmul ins(%A, %B : !row_major_A, !row_major_B)
    outs(%C_ref: !row_major_C)
  %act2 = memref.cast %C : !row_major_C to memref<*xf32>
  %exp2 = memref.cast %C_ref : !row_major_C to memref<*xf32>
  %errors2 = call @verifyMemRefF32(%act2, %exp2) : (memref<*xf32>, memref<*xf32>) -> i64
  vector.print %errors2 : i64
  memref.dealloc %C_ref : !row_major_C

  memref.dealloc %A : !row_major_A
  memref.dealloc %B : !row_major_B
  memref.dealloc %C : !row_major_C

  memref.dealloc %cA : !column_major_A
  memref.dealloc %cB : !column_major_B
  memref.dealloc %cC : !column_major_C

  return
}

func private @rtclock() -> f64
func private @verifyMemRefF32(memref<*xf32>, memref<*xf32>) -> i64 attributes { llvm.emit_c_interface }

// TODO: init with random, run and check output.
// func private @fill_random_f32(memref<*xf32>)
