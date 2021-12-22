; RUN: llc < %s -O2 -mtriple=x86_64-unknown-linux-gnu -x86-indirect-branch-tracking | FileCheck %s --check-prefix=CHECK-IBT-PRECEDING-ENDBR

; CHECK-IBT-PRECEDING-ENDBR: endbr
; CHECK-IBT-PRECEDING-ENDBR: bar:
; CHECK-IBT-PRECEDING-ENDBR-NOT: endbr
; CHECK-IBT-PRECEDING-ENDBR: movq
; CHECK-IBT-PRECEDING-ENDBR: subq $4
; CHECK-IBT-PRECEDING-ENDBR: callq *%
; CHECK-IBT-PRECEDING-ENDBR: subq $4
; CHECK-IBT-PRECEDING-ENDBR: callq *%
; CHECK-IBT-PRECEDING-ENDBR: callq foo

target triple = "x86_64-unknown-linux-gnu"

@fptr = dso_local local_unnamed_addr global void ()* @foo, align 8

declare dso_local void @foo() #0

define dso_local void @bar(i8* ()* nocapture %0) local_unnamed_addr #1 {
  %2 = load void ()*, void ()** @fptr, align 8
  call void %2() #2
  %3 = call i8* %0()
  call void @foo()
  ret void
}

!llvm.module.flags = !{!0}
!0 = !{i32 4, !"ibt-preceding-endbr", i32 1}
