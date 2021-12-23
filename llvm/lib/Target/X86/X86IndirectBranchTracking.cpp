//===---- X86IndirectBranchTracking.cpp - Enables CET IBT mechanism -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines a pass that enables Indirect Branch Tracking (IBT) as part
// of Control-Flow Enforcement Technology (CET).
// The pass adds ENDBR (End Branch) machine instructions at the beginning of
// each basic block or function that is referenced by an indrect jump/call
// instruction.
// The ENDBR instructions have a NOP encoding and as such are ignored in
// targets that do not support CET IBT mechanism.
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"

using namespace llvm;

#define DEBUG_TYPE "x86-indirect-branch-tracking"
#define ENDBR_LEN 4

cl::opt<bool> IndirectBranchTracking(
    "x86-indirect-branch-tracking", cl::init(false), cl::Hidden,
    cl::desc("Enable X86 indirect branch tracking pass."));

STATISTIC(NumEndBranchAdded, "Number of ENDBR instructions added");

namespace {
class X86IndirectBranchTrackingPass : public MachineFunctionPass {
public:
  X86IndirectBranchTrackingPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "X86 Indirect Branch Tracking";
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  static char ID;

  /// Machine instruction info used throughout the class.
  const X86InstrInfo *TII = nullptr;

  /// Endbr opcode for the current machine function.
  unsigned int EndbrOpcode = 0;

  /// Adds a new ENDBR instruction to the beginning of the MBB.
  /// The function will not add it if already exists.
  /// It will add ENDBR32 or ENDBR64 opcode, depending on the target.
  /// \returns true if the ENDBR was added and false otherwise.
  bool addENDBR(MachineBasicBlock &MBB, MachineBasicBlock::iterator I) const;

  /// Checks if the function should get an ENDBR instruction in its prologue.
  bool needsPrologueENDBR(const Function *F, const Module *M, const X86TargetMachine *TM) const;

  /// Adds +4 offset to direct calls that are targeting an ENDBR instruction,
  /// preventing control-flow from decoding superfluous instructions.
  /// Used when -mibt-fix-direct is used
  bool fixDirectCalls(MachineFunction &MF, const Module *M) const;

  /// Adds -4 offset to indirect calls, for when ENDBR is placed before the
  /// function entry label. Used when -ibt-preceding-endbr is used.
  bool fixIndirectCalls(MachineFunction &MF) const;
};

} // end anonymous namespace

char X86IndirectBranchTrackingPass::ID = 0;

FunctionPass *llvm::createX86IndirectBranchTrackingPass() {
  return new X86IndirectBranchTrackingPass();
}

static bool IsCallReturnTwice(llvm::MachineOperand &MOp) {
  if (!MOp.isGlobal())
    return false;
  auto *CalleeFn = dyn_cast<Function>(MOp.getGlobal());
  if (!CalleeFn)
    return false;
  AttributeList Attrs = CalleeFn->getAttributes();
  return Attrs.hasFnAttr(Attribute::ReturnsTwice);
}

static bool IsWeakAliasee(const Function *F) {
  const Module *M = F->getParent();
  for (auto &A : M->aliases()) {
    if (A.getAliasee() == F && A.hasWeakLinkage())
      return true;
  }
  return false;
}

bool X86IndirectBranchTrackingPass::addENDBR(
    MachineBasicBlock &MBB, MachineBasicBlock::iterator I) const {
  assert(TII && "Target instruction info was not initialized");
  assert((X86::ENDBR64 == EndbrOpcode || X86::ENDBR32 == EndbrOpcode) &&
         "Unexpected Endbr opcode");

  // If the MBB/I is empty or the current instruction is not ENDBR,
  // insert ENDBR instruction to the location of I.
  if (I == MBB.end() || I->getOpcode() != EndbrOpcode) {
    BuildMI(MBB, I, MBB.findDebugLoc(I), TII->get(EndbrOpcode));
    ++NumEndBranchAdded;
    return true;
  }
  return false;
}

// Checks if function should have an ENDBR in its prologue
bool X86IndirectBranchTrackingPass::needsPrologueENDBR(const Function *F, const Module *M, const X86TargetMachine *TM) const {
  if (F->doesNoCfCheck())
    return false;

  Metadata *IBTSeal = M->getModuleFlag("ibt-seal");

  switch (TM->getCodeModel()) {
  // Large code model functions always reachable through indirect calls.
  case CodeModel::Large:
    return true;
  // Only address taken functions in LTO'ed kernel are reachable indirectly.
  // IBTSeal implies LTO, thus only check if function is address taken.
  case CodeModel::Kernel:
    // Check if ibt-seal was enabled (implies LTO is being used).
    if (IBTSeal) {
      return F->hasAddressTaken();
    }
    // if !IBTSeal, fall into default case.
    LLVM_FALLTHROUGH;
  // Address taken or externally linked functions may be reachable.
  default:
    return (F->hasAddressTaken() || !F->hasLocalLinkage());
  }
}

bool X86IndirectBranchTrackingPass::fixIndirectCalls(MachineFunction &MF) const {
  bool Changed = false;
  bool Deref;
  bool Preserve;
  RegScavenger RS;

  const X86Subtarget &SubTarget = MF.getSubtarget<X86Subtarget>();
  auto TII = SubTarget.getInstrInfo();

  for (auto &BB : MF) {
    MachineBasicBlock::iterator I = BB.begin();
    MachineBasicBlock::iterator IE = BB.end();
    for (; I != IE; I++) {
      unsigned Opcode = I->getOpcode();
      unsigned Reg;

      switch(Opcode) {
        // TODO: Verify if support for JMPXXr/JMPXXm is required (probably not).
        case X86::CALL64r:
        case X86::TAILJMPr64:
        case X86::TAILJMPr:
        case X86::TAILJMPr64_REX:
          Deref = false;
          break;
        // if this is CALL64m we need to dereference the pointer before sub.
        case X86::CALL64m:
        case X86::TAILJMPm64:
        case X86::TAILJMPm64_REX:
        case X86::TAILJMPm:
          Deref = true;
          break;
        default:
          continue;
      }

      Changed = true;

      // Check if we need to preserve the pointer contents after the call
      MachineOperand &MO = I->getOperand(0);
      Reg = MO.getReg();
      if (!MO.isKill())
        Preserve = true;
      else
        Preserve = false;

      if (Deref) {
        // If we can't clobber the register, we need a free one.
        if (Preserve) {
          RS.enterBasicBlock(BB);
          RS.forward(I);
          Reg = RS.FindUnusedReg(&X86::GR64RegClass);
          // Assuming this is CALL, scratch-regs should always be available...
          // either way, check just in case.
          if (!Reg) {
            WithColor::warning() << "IBT: Regs no available in "
              << MF.getName() << ". Fallbacking into R10.\n";
            Reg = X86::R10;
          }
        }
        // Load CALL64m pointer from memory, so we can adjust the offset.
        // This MOV will be placed before the SUB in the final binary.
        auto MIB = BuildMI(BB, I, DebugLoc(), TII->get(X86::MOV64rm), Reg);
        for (unsigned int i = 0; i < I->getNumOperands(); i++) {
          MO = I->getOperand(i);
          MIB.add(I->getOperand(i));
        }

        BuildMI(BB, I, DebugLoc(), TII->get(X86::SUB64ri8), Reg)
          .addReg(Reg)
          .addImm(0x4);

        // replace the memory-based operation by a reg-based operation
        if (Opcode == X86::CALL64m) {
          MIB = BuildMI(BB, I, DebugLoc(), TII->get(X86::CALL64r), Reg);
        } else {
          MIB = BuildMI(BB, I, DebugLoc(), TII->get(X86::TAILJMPr64), Reg);
        }
        I->removeFromParent();
        I = *MIB;
      } else {
        BuildMI(BB, I, DebugLoc(), TII->get(X86::SUB64ri8), Reg)
          .addReg(Reg)
          .addImm(0x4);

        // if calling from reg that needs to be preserved, restore its value.
        if (Preserve) {
          BuildMI(BB, std::next(I), DebugLoc(), TII->get(X86::ADD64ri8), Reg)
            .addReg(Reg)
            .addImm(0x4);
        }
      }
    }
  }
  return Changed;
}

bool X86IndirectBranchTrackingPass::fixDirectCalls(MachineFunction &MF, const Module *M) const {
  bool Changed = false;
  for (auto &BB : MF) {
    for (auto &I : BB) {
      switch(I.getOpcode()) {
        case X86::CALL64pcrel32:
        case X86::TAILJMPd:
        case X86::TAILJMPd64_CC:
        case X86::TAILJMPd_CC:
        case X86::TAILJMPd64:
          break;
        default:
          continue;
      }
      auto &O = I.getOperand(0);
      if (O.getOffset()) {
        LLVM_DEBUG(StringRef name = MF.getName();
            WithColor::Warning << "X86/IBT: Duplicated offset for "
            "ENDBR in " << name << "\n";);
        continue;
      }

      // We don't know if Symbols/MCSymbols are emitted with ENDBR, so we
      // skip and don't fix direct calls to these.
      // if (O.isSymbol() || O.isMCSymbol()) {
      //    O.setOffset(ENDBR_LEN);
      //    continue;
      // }

      if (O.isGlobal()) {
        const Value *Target = O.getGlobal();
        const GlobalAlias *GAlias = dyn_cast_or_null<GlobalAlias>(Target);

        // TODO: These aliasing checks may not be needed with LTO. Handle it.
        if (GAlias && GAlias->hasWeakLinkage()) {
          // We can't assume if a weak alias will be ENDBR'ed, so just skip.
          continue;
        } else {
          // If not a weak alias, we should be able to get the call target.
          // Check if static, addr-taken or weak-aliasee then fix call offset.
          Target = Target->stripPointerCastsAndAliases();
          if (!Target) {
            LLVM_DEBUG(StringRef name = MF.getName();
                WithColor::Warning << "X86/IBT: Unknown alias target"
                " in " << name << "\n";);
            continue;
          }
          const Function *F = dyn_cast_or_null<Function>(Target);
          if (!F) {
            LLVM_DEBUG(StringRef name = MF.getName();
                WithColor::Warning << "X86/IBT: Unknown alias target"
                " in " << name << "\n";);
            continue;
          }
          if (IsWeakAliasee(F)) {
            LLVM_DEBUG(StringRef name = MF.getName();
                WithColor::Warning << "X86/IBT: Can't fix direct call"
                " in " << name << "\n";);
            continue;
          }
          const X86TargetMachine *TM =
            static_cast<const X86TargetMachine *>(&MF.getTarget());
            if (needsPrologueENDBR(F, M, TM) && !F->isDeclaration()) {
              LLVM_DEBUG(StringRef name = MF.getName();
                  WithColor::Warning << "X86/IBT: Direct call fixed"
                  " in " << name << "\n";);
              O.setOffset(ENDBR_LEN);
              Changed = true;
            }
        }
      }
    }
  }
  return Changed;
}

bool X86IndirectBranchTrackingPass::runOnMachineFunction(MachineFunction &MF) {
  const X86Subtarget &SubTarget = MF.getSubtarget<X86Subtarget>();

  const Module *M = MF.getMMI().getModule();
  // Check that the cf-protection-branch is enabled.
  Metadata *isCFProtectionSupported = M->getModuleFlag("cf-protection-branch");

  //  NB: We need to enable IBT in jitted code if JIT compiler is CET
  //  enabled.
  const X86TargetMachine *TM =
      static_cast<const X86TargetMachine *>(&MF.getTarget());
#ifdef __CET__
  bool isJITwithCET = TM->isJIT();
#else
  bool isJITwithCET = false;
#endif
  if (!isCFProtectionSupported && !IndirectBranchTracking && !isJITwithCET)
    return false;

  // True if the current MF was changed and false otherwise.
  bool Changed = false;

  TII = SubTarget.getInstrInfo();
  EndbrOpcode = SubTarget.is64Bit() ? X86::ENDBR64 : X86::ENDBR32;

  // If function is reachable indirectly, mark the first BB with ENDBR.
  if (needsPrologueENDBR(&MF.getFunction(), M, TM)) {
    auto MBB = MF.begin();
    Changed |= addENDBR(*MBB, MBB->begin());
  }

  Metadata *IBTFixDirectCalls = M->getModuleFlag("ibt-fix-direct");
  if (IBTFixDirectCalls)
    Changed |= fixDirectCalls(MF, M);

  Metadata *IBTPrecedingEndbr = M->getModuleFlag("ibt-preceding-endbr");
  if (IBTPrecedingEndbr)
    Changed |= fixIndirectCalls(MF);

  for (auto &MBB : MF) {
    // Find all basic blocks that their address was taken (for example
    // in the case of indirect jump) and add ENDBR instruction.
    if (MBB.hasAddressTaken())
      Changed |= addENDBR(MBB, MBB.begin());

    for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
      if (I->isCall() && I->getNumOperands() > 0 &&
          IsCallReturnTwice(I->getOperand(0))) {
        Changed |= addENDBR(MBB, std::next(I));
      }
    }

    // Exception handle may indirectly jump to catch pad, So we should add
    // ENDBR before catch pad instructions. For SjLj exception model, it will
    // create a new BB(new landingpad) indirectly jump to the old landingpad.
    if (TM->Options.ExceptionModel == ExceptionHandling::SjLj) {
      for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
        // New Landingpad BB without EHLabel.
        if (MBB.isEHPad()) {
          if (I->isDebugInstr())
            continue;
          Changed |= addENDBR(MBB, I);
          break;
        } else if (I->isEHLabel()) {
          // Old Landingpad BB (is not Landingpad now) with
          // the the old "callee" EHLabel.
          MCSymbol *Sym = I->getOperand(0).getMCSymbol();
          if (!MF.hasCallSiteLandingPad(Sym))
            continue;
          Changed |= addENDBR(MBB, std::next(I));
          break;
        }
      }
    } else if (MBB.isEHPad()){
      for (MachineBasicBlock::iterator I = MBB.begin(); I != MBB.end(); ++I) {
        if (!I->isEHLabel())
          continue;
        Changed |= addENDBR(MBB, std::next(I));
        break;
      }
    }
  }
  return Changed;
}
