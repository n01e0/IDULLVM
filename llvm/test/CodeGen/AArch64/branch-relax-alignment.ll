; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=aarch64-apple-darwin -aarch64-bcc-offset-bits=4 -align-all-nofallthru-blocks=4 < %s | FileCheck %s

; Long branch is assumed because the block has a higher alignment
; requirement than the function.

define i32 @invert_bcc_block_align_higher_func(i32 %x, i32 %y) align 4 #0 {
; CHECK-LABEL: invert_bcc_block_align_higher_func:
; CHECK:       ; %bb.0: ; %common.ret
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    mov w8, #9
; CHECK-NEXT:    mov w9, #42
; CHECK-NEXT:    cset w0, ne
; CHECK-NEXT:    csel w8, w9, w8, eq
; CHECK-NEXT:    str w8, [x8]
; CHECK-NEXT:    ret
  %1 = icmp eq i32 %x, %y
  br i1 %1, label %bb1, label %bb2

bb2:
  store volatile i32 9, i32* undef
  ret i32 1

bb1:
  store volatile i32 42, i32* undef
  ret i32 0
}

attributes #0 = { nounwind }