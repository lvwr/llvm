; RUN: llc < %s -O2 -mtriple=x86_64-unknown-linux-gnu -x86-indirect-branch-tracking | FileCheck %s --check-prefix=CHECK-IBT-FIX-DIRECT

; CHECK-IBT-FIX-DIRECT: foo:
; CHECK-IBT-FIX-DIRECT: endbr
; CHECK-IBT-FIX-DIRECT: bar:
; CHECK-IBT-FIX-DIRECT-NOT: endbr
; CHECK-IBT-FIX-DIRECT: callq *
; CHECK-IBT-FIX-DIRECT: callq foo+4
; CHECK-IBT-FIX-DIRECT-NOT: callq bar+4

target triple = "x86_64-unknown-linux-gnu"

define dso_local void @foo() {
  ret void
}

define internal void @bar() {
  %1 = alloca void (...)*, align 8
  store void (...)* bitcast (void ()* @foo to void (...)*), void (...)** %1, align 8
  %2 = load void (...)*, void (...)** %1, align 8
  call void (...) %2()
  call void @foo()
  call void @bar()
  ret void
}

!llvm.module.flags = !{!1}
!1 = !{i32 4, !"ibt-fix-direct", i32 1}
