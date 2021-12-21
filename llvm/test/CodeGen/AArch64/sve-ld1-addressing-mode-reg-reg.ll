; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=aarch64-linux-gnu -mattr=+sve,+bf16 < %s | FileCheck %s

; LD1B

define <vscale x 16 x i8> @ld1_nxv16i8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv16i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.b
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 16 x i8>*
  %val = load volatile <vscale x 16 x i8>, <vscale x 16 x i8>* %ptrcast
  ret <vscale x 16 x i8> %val
}

define <vscale x 8 x i16> @ld1_nxv16i8_bitcast_to_i16(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv16i8_bitcast_to_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.b
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 8 x i16>*
  %val = load volatile <vscale x 8 x i16>, <vscale x 8 x i16>* %ptrcast
  ret <vscale x 8 x i16> %val
}

define <vscale x 4 x i32> @ld1_nxv16i8_bitcast_to_i32(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv16i8_bitcast_to_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.b
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 4 x i32>*
  %val = load volatile <vscale x 4 x i32>, <vscale x 4 x i32>* %ptrcast
  ret <vscale x 4 x i32> %val
}

define <vscale x 2 x i64> @ld1_nxv16i8_bitcast_to_i64(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv16i8_bitcast_to_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.b
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 2 x i64>*
  %val = load volatile <vscale x 2 x i64>, <vscale x 2 x i64>* %ptrcast
  ret <vscale x 2 x i64> %val
}

define <vscale x 8 x i16> @ld1_nxv8i16_zext8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv8i16_zext8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.h
; CHECK-NEXT:    ld1b { z0.h }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 8 x i8>*
  %val = load volatile <vscale x 8 x i8>, <vscale x 8 x i8>* %ptrcast
  %zext = zext <vscale x 8 x i8> %val to <vscale x 8 x i16>
  ret <vscale x 8 x i16> %zext
}

define <vscale x 4 x i32> @ld1_nxv4i32_zext8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4i32_zext8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1b { z0.s }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 4 x i8>*
  %val = load volatile <vscale x 4 x i8>, <vscale x 4 x i8>* %ptrcast
  %zext = zext <vscale x 4 x i8> %val to <vscale x 4 x i32>
  ret <vscale x 4 x i32> %zext
}

define <vscale x 2 x i64> @ld1_nxv2i64_zext8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64_zext8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1b { z0.d }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 2 x i8>*
  %val = load volatile <vscale x 2 x i8>, <vscale x 2 x i8>* %ptrcast
  %zext = zext <vscale x 2 x i8> %val to <vscale x 2 x i64>
  ret <vscale x 2 x i64> %zext
}

define <vscale x 8 x i16> @ld1_nxv8i16_sext8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv8i16_sext8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.h
; CHECK-NEXT:    ld1sb { z0.h }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 8 x i8>*
  %val = load volatile <vscale x 8 x i8>, <vscale x 8 x i8>* %ptrcast
  %sext = sext <vscale x 8 x i8> %val to <vscale x 8 x i16>
  ret <vscale x 8 x i16> %sext
}

define <vscale x 4 x i32> @ld1_nxv4i32_sext8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4i32_sext8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1sb { z0.s }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 4 x i8>*
  %val = load volatile <vscale x 4 x i8>, <vscale x 4 x i8>* %ptrcast
  %sext = sext <vscale x 4 x i8> %val to <vscale x 4 x i32>
  ret <vscale x 4 x i32> %sext
}

define <vscale x 2 x i64> @ld1_nxv2i64_sext8(i8* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64_sext8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1sb { z0.d }, p0/z, [x0, x1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i8, i8* %addr, i64 %off
  %ptrcast = bitcast i8* %ptr to <vscale x 2 x i8>*
  %val = load volatile <vscale x 2 x i8>, <vscale x 2 x i8>* %ptrcast
  %sext = sext <vscale x 2 x i8> %val to <vscale x 2 x i64>
  ret <vscale x 2 x i64> %sext
}

; LD1H

define <vscale x 8 x i16> @ld1_nxv8i16(i16* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv8i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.h
; CHECK-NEXT:    ld1h { z0.h }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i16, i16* %addr, i64 %off
  %ptrcast = bitcast i16* %ptr to <vscale x 8 x i16>*
  %val = load volatile <vscale x 8 x i16>, <vscale x 8 x i16>* %ptrcast
  ret <vscale x 8 x i16> %val
}

define <vscale x 4 x i32> @ld1_nxv4i32_zext16(i16* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4i32_zext16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1h { z0.s }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i16, i16* %addr, i64 %off
  %ptrcast = bitcast i16* %ptr to <vscale x 4 x i16>*
  %val = load volatile <vscale x 4 x i16>, <vscale x 4 x i16>* %ptrcast
  %zext = zext <vscale x 4 x i16> %val to <vscale x 4 x i32>
  ret <vscale x 4 x i32> %zext
}

define <vscale x 2 x i64> @ld1_nxv2i64_zext16(i16* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64_zext16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1h { z0.d }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i16, i16* %addr, i64 %off
  %ptrcast = bitcast i16* %ptr to <vscale x 2 x i16>*
  %val = load volatile <vscale x 2 x i16>, <vscale x 2 x i16>* %ptrcast
  %zext = zext <vscale x 2 x i16> %val to <vscale x 2 x i64>
  ret <vscale x 2 x i64> %zext
}

define <vscale x 4 x i32> @ld1_nxv4i32_sext16(i16* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4i32_sext16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1sh { z0.s }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i16, i16* %addr, i64 %off
  %ptrcast = bitcast i16* %ptr to <vscale x 4 x i16>*
  %val = load volatile <vscale x 4 x i16>, <vscale x 4 x i16>* %ptrcast
  %sext = sext <vscale x 4 x i16> %val to <vscale x 4 x i32>
  ret <vscale x 4 x i32> %sext
}

define <vscale x 2 x i64> @ld1_nxv2i64_sext16(i16* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64_sext16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1sh { z0.d }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i16, i16* %addr, i64 %off
  %ptrcast = bitcast i16* %ptr to <vscale x 2 x i16>*
  %val = load volatile <vscale x 2 x i16>, <vscale x 2 x i16>* %ptrcast
  %sext = sext <vscale x 2 x i16> %val to <vscale x 2 x i64>
  ret <vscale x 2 x i64> %sext
}

define <vscale x 8 x half> @ld1_nxv8f16(half* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.h
; CHECK-NEXT:    ld1h { z0.h }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds half, half* %addr, i64 %off
  %ptrcast = bitcast half* %ptr to <vscale x 8 x half>*
  %val = load volatile <vscale x 8 x half>, <vscale x 8 x half>* %ptrcast
  ret <vscale x 8 x half> %val
}

define <vscale x 8 x bfloat> @ld1_nxv8bf16(bfloat* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv8bf16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.h
; CHECK-NEXT:    ld1h { z0.h }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds bfloat, bfloat* %addr, i64 %off
  %ptrcast = bitcast bfloat* %ptr to <vscale x 8 x bfloat>*
  %val = load volatile <vscale x 8 x bfloat>, <vscale x 8 x bfloat>* %ptrcast
  ret <vscale x 8 x bfloat> %val
}

define <vscale x 4 x half> @ld1_nxv4f16(half* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1h { z0.s }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds half, half* %addr, i64 %off
  %ptrcast = bitcast half* %ptr to <vscale x 4 x half>*
  %val = load volatile <vscale x 4 x half>, <vscale x 4 x half>* %ptrcast
  ret <vscale x 4 x half> %val
}

define <vscale x 2 x half> @ld1_nxv2f16(half* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1h { z0.d }, p0/z, [x0, x1, lsl #1]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds half, half* %addr, i64 %off
  %ptrcast = bitcast half* %ptr to <vscale x 2 x half>*
  %val = load volatile <vscale x 2 x half>, <vscale x 2 x half>* %ptrcast
  ret <vscale x 2 x half> %val
}

; LD1W

define <vscale x 4 x i32> @ld1_nxv4i32(i32* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1w { z0.s }, p0/z, [x0, x1, lsl #2]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i32, i32* %addr, i64 %off
  %ptrcast = bitcast i32* %ptr to <vscale x 4 x i32>*
  %val = load volatile <vscale x 4 x i32>, <vscale x 4 x i32>* %ptrcast
  ret <vscale x 4 x i32> %val
}

define <vscale x 2 x i64> @ld1_nxv2i64_zext32(i32* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64_zext32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1w { z0.d }, p0/z, [x0, x1, lsl #2]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i32, i32* %addr, i64 %off
  %ptrcast = bitcast i32* %ptr to <vscale x 2 x i32>*
  %val = load volatile <vscale x 2 x i32>, <vscale x 2 x i32>* %ptrcast
  %zext = zext <vscale x 2 x i32> %val to <vscale x 2 x i64>
  ret <vscale x 2 x i64> %zext
}

define <vscale x 2 x i64> @ld1_nxv2i64_sext32(i32* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64_sext32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1sw { z0.d }, p0/z, [x0, x1, lsl #2]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i32, i32* %addr, i64 %off
  %ptrcast = bitcast i32* %ptr to <vscale x 2 x i32>*
  %val = load volatile <vscale x 2 x i32>, <vscale x 2 x i32>* %ptrcast
  %sext = sext <vscale x 2 x i32> %val to <vscale x 2 x i64>
  ret <vscale x 2 x i64> %sext
}

define <vscale x 4 x float> @ld1_nxv4f32(float* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s
; CHECK-NEXT:    ld1w { z0.s }, p0/z, [x0, x1, lsl #2]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds float, float* %addr, i64 %off
  %ptrcast = bitcast float* %ptr to <vscale x 4 x float>*
  %val = load volatile <vscale x 4 x float>, <vscale x 4 x float>* %ptrcast
  ret <vscale x 4 x float> %val
}

define <vscale x 2 x float> @ld1_nxv2f32(float* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1w { z0.d }, p0/z, [x0, x1, lsl #2]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds float, float* %addr, i64 %off
  %ptrcast = bitcast float* %ptr to <vscale x 2 x float>*
  %val = load volatile <vscale x 2 x float>, <vscale x 2 x float>* %ptrcast
  ret <vscale x 2 x float> %val
}

; LD1D

define <vscale x 2 x i64> @ld1_nxv2i64(i64* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1d { z0.d }, p0/z, [x0, x1, lsl #3]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds i64, i64* %addr, i64 %off
  %ptrcast = bitcast i64* %ptr to <vscale x 2 x i64>*
  %val = load volatile <vscale x 2 x i64>, <vscale x 2 x i64>* %ptrcast
  ret <vscale x 2 x i64> %val
}

define <vscale x 2 x double> @ld1_nxv2f64(double* %addr, i64 %off) {
; CHECK-LABEL: ld1_nxv2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d
; CHECK-NEXT:    ld1d { z0.d }, p0/z, [x0, x1, lsl #3]
; CHECK-NEXT:    ret
  %ptr = getelementptr inbounds double, double* %addr, i64 %off
  %ptrcast = bitcast double* %ptr to <vscale x 2 x double>*
  %val = load volatile <vscale x 2 x double>, <vscale x 2 x double>* %ptrcast
  ret <vscale x 2 x double> %val
}