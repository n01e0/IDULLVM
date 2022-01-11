#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86InstrBuilder.h"
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
#include <random>

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
  void obfuscateLiteralOperand(MachineFunction &, MachineInstr &, unsigned);
  MachineBasicBlock::instr_iterator skip(MachineBasicBlock *, unsigned);
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

  MRI = &MF.getRegInfo();
  TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();
  TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();


  if (!EnableEncodeLiterals)
    return false;

  for (auto &MBB : MF) {
    unsigned Index = 0;
    for (MachineBasicBlock::iterator MI = MBB.begin(), E = MBB.end(); MI != E; ++MI, ++Index) {
      if (isStoreLocalValue(*MI)) {
        obfuscateLiteralOperand(MF, *MI, Index);
        Changed = true;
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

MachineBasicBlock::instr_iterator X86EncodeLiteralsPass::skip(MachineBasicBlock *MBB, unsigned Index) {
  auto I = MBB->instr_begin();
  auto E = MBB->instr_end();
  unsigned Cur = 0;
  while (I != E && Cur != Index)
    ++I, ++Cur;
  return ++I;
}

void X86EncodeLiteralsPass::obfuscateLiteralOperand(MachineFunction &MF, MachineInstr &MI, unsigned Index) {
  MachineOperand &Lit = getLiteralOperand(MI);
  MachineBasicBlock *PMBB = MI.getParent();
  MachineBasicBlock::instr_iterator Iter = skip(PMBB, Index);
  unsigned LitOffset = MI.getNumOperands() - 1;
  int64_t Offset = MI.getOperand(3).getImm();
  
  switch (MI.getOpcode()) {
    case X86::MOV8mi:{
      std::random_device seed_gen;
      std::mt19937_64 mt(seed_gen());
      uint8_t Rnd = (uint8_t)(mt() & 0xff);
      uint8_t Imm = (uint8_t)Lit.getImm();
      unsigned XOROpc = X86::XOR8mi;
      // replace literal operand by rnd
      MI.RemoveOperand(LitOffset);
      MachineOperand OpRnd = MachineOperand::CreateImm(Rnd);
      MI.addOperand(OpRnd);
      
      addRegOffset(BuildMI(*PMBB, Iter, MI.getDebugLoc(), TII->get(XOROpc)), X86::RBP, true, Offset)
        .addImm(Rnd ^ Imm);
      break;
    }
    case X86::MOV16mi:{
      std::random_device seed_gen;
      std::mt19937_64 mt(seed_gen());
      uint16_t Rnd = (uint16_t)(mt() & 0xffff);
      uint16_t Imm = (uint16_t)Lit.getImm();
      unsigned XOROpc = X86::XOR16mi;
      // replace literal operand by rnd
      MI.RemoveOperand(LitOffset);
      MachineOperand OpRnd = MachineOperand::CreateImm(Rnd);
      MI.addOperand(OpRnd);
      
      addRegOffset(BuildMI(*PMBB, Iter, MI.getDebugLoc(), TII->get(XOROpc)), X86::RBP, true, Offset)
        .addImm(Rnd ^ Imm);
      break;
    }
    case X86::MOV32mi:{
      std::random_device seed_gen;
      std::mt19937_64 mt(seed_gen());
      uint32_t Rnd = (uint32_t)(mt() & 0xffffffff);
      uint32_t Imm = (uint32_t)Lit.getImm();
      unsigned XOROpc = X86::XOR32mi;
      // replace literal operand by rnd
      MI.RemoveOperand(LitOffset);
      MachineOperand OpRnd = MachineOperand::CreateImm(Rnd);
      MI.addOperand(OpRnd);
      
      addRegOffset(BuildMI(*PMBB, Iter, MI.getDebugLoc(), TII->get(XOROpc)), X86::RBP, true, Offset)
        .addImm(Rnd ^ Imm);
      break;
    }
    case X86::MOV64mi32:{
      std::random_device seed_gen;
      std::mt19937_64 mt(seed_gen());
      uint32_t Rnd = (uint32_t)(mt() & 0xffffffff);
      uint32_t Imm = (uint32_t)Lit.getImm();
      unsigned XOROpc = X86::XOR64mi32;
      // replace literal operand by rnd
      MI.RemoveOperand(LitOffset);
      MachineOperand OpRnd = MachineOperand::CreateImm(Rnd);
      MI.addOperand(OpRnd);
      
      addRegOffset(BuildMI(*PMBB, Iter, MI.getDebugLoc(), TII->get(XOROpc)), X86::RBP, true, Offset)
        .addImm(Rnd ^ Imm);
      break;
    }
    default:
      assert(1 && "unreachable");
  }
}
