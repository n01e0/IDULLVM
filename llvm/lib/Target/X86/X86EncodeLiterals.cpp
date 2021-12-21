#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <cstdint>

using namespace llvm;

#define DEBUG_TYPE "X86-encode-literals"

static cl::opt<bool> EnableEncodeLiterals("enable-encode-literals",
                                          cl::desc("X86: Encode Literals"),
                                          cl::init(false));

namespace {

class X86EncodeLiteralsPass : public MachineFunctionPass {
public:
  X86EncodeLiteralsPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "X86 Encode Literals"; }

  /// Loop over all of the basic blocks, encoding literals.
  bool runOnMachineFunction(MachineFunction &MF) override;

  static char ID;

private:
  MachineRegisterInfo *MRI = nullptr;
  const X86InstrInfo *TII = nullptr;
  const X86RegisterInfo *TRI = nullptr;

  bool isStoreLocalValue(MachineInstr &);
  MachineOperand &getLiteralOperand(MachineInstr &);
};

} // end anonymous namespace

char X86EncodeLiteralsPass::ID = 0;

FunctionPass *llvm::createX86EncodeLiterals() {
  return new X86EncodeLiteralsPass();
}
INITIALIZE_PASS(X86EncodeLiteralsPass, DEBUG_TYPE, "X86 Encode Literals pass",
                false, false)

bool X86EncodeLiteralsPass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;

  if (!EnableEncodeLiterals)
    return false;

  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if (isStoreLocalValue(MI)) {
        MachineOperand &Lit = getLiteralOperand(MI);
        errs() << Lit << "\n";
      }
    }
  }

  return Changed;
}

bool X86EncodeLiteralsPass::isStoreLocalValue(MachineInstr &MI) {
  unsigned Opcode = MI.getOpcode();
  return Opcode == X86::MOV8mi || Opcode == X86::MOV16mi ||
         Opcode == X86::MOV32mi || Opcode == X86::MOV64mi32;
}

MachineOperand &X86EncodeLiteralsPass::getLiteralOperand(MachineInstr &MI) {
  MachineOperand &Lit = MI.getOperand(MI.getNumOperands() - 1);
  assert(Lit.isImm());
  return Lit;
}


