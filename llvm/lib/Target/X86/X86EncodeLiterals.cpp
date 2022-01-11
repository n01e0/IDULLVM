#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86InstrBuilder.h"
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
#include <bits/stdint-uintn.h>
#include <cassert>
#include <cstdint>
#include <random>

using namespace llvm;

#define DEBUG_TYPE "X86-encode-literals"

static cl::opt<bool> EnableEncodeLiterals("enable-encode-literals",
                                          cl::desc("X86: Encode Literals"),
                                          cl::init(false));

static inline bool isStoreLocalValue(MachineInstr &MI);

MachineBasicBlock::instr_iterator skip(MachineBasicBlock *MBB, unsigned Index);

static inline unsigned getXorOpc(MachineInstr &MI);

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
  inline void buildXor(MachineInstr &MI, unsigned Index, uint64_t Operand);


  MachineOperand &getLiteralOperand(MachineInstr &MI, unsigned Offset);
  void obfuscateLiteralOperand(MachineFunction &MF, MachineInstr &MI, unsigned Index);
};

} // end anonymous namespace

char X86EncodeLiteralsPass::ID = 0;

FunctionPass *llvm::createX86EncodeLiterals() {
  return new X86EncodeLiteralsPass();
}
INITIALIZE_PASS(X86EncodeLiteralsPass, DEBUG_TYPE, "X86 Encode Literals pass",
                false, false)

static inline bool isStoreLocalValue(MachineInstr &MI) {
  unsigned Opcode = MI.getOpcode();
  return Opcode == X86::MOV8mi || Opcode == X86::MOV16mi ||
         Opcode == X86::MOV32mi || Opcode == X86::MOV64mi32;
}

MachineBasicBlock::instr_iterator
skip(MachineBasicBlock *MBB, unsigned Index) {
  auto I = MBB->instr_begin();
  auto E = MBB->instr_end();
  unsigned Cur = 0;
  while (I != E && Cur != Index)
    ++I, ++Cur;
  return ++I;
}

static inline unsigned getXorOpc(MachineInstr &MI) {
  assert(isStoreLocalValue(MI));
  switch (MI.getOpcode()) {
    case X86::MOV8mi:
      return X86::XOR8mi;
    case X86::MOV16mi:
      return X86::XOR16mi;
    case X86::MOV32mi:
      return X86::XOR32mi;
    case X86::MOV64mi32:
      return X86::XOR64mi32;
    default:
      assert(1 && "unreachable");
      return 0;
  }
}

inline void X86EncodeLiteralsPass::buildXor(MachineInstr &MI, unsigned Index, uint64_t Operand) {
  MachineBasicBlock *PMBB = MI.getParent();
  MachineBasicBlock::instr_iterator Iter = skip(PMBB, Index);
  int64_t Offset = MI.getOperand(3).getImm();
  unsigned XOROpc = getXorOpc(MI);

  addRegOffset(BuildMI(*PMBB, Iter, MI.getDebugLoc(), TII->get(XOROpc)),
               X86::RBP, true, Offset)
      .addImm(Operand);
}

bool X86EncodeLiteralsPass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;

  MRI = &MF.getRegInfo();
  TII = MF.getSubtarget<X86Subtarget>().getInstrInfo();
  TRI = MF.getSubtarget<X86Subtarget>().getRegisterInfo();

  if (!EnableEncodeLiterals)
    return false;

  for (auto &MBB : MF) {
    unsigned Index = 0;
    for (MachineBasicBlock::iterator MI = MBB.begin(), E = MBB.end(); MI != E;
         ++MI, ++Index) {
      if (isStoreLocalValue(*MI)) {
        obfuscateLiteralOperand(MF, *MI, Index);
        Changed = true;
      }
    }
  }

  return Changed;
}

MachineOperand &X86EncodeLiteralsPass::getLiteralOperand(MachineInstr &MI, unsigned Offset) {
  MachineOperand &Lit = MI.getOperand(MI.getNumOperands() - 1);
  assert(Lit.isImm());
  return Lit;
}

void X86EncodeLiteralsPass::obfuscateLiteralOperand(MachineFunction &MF,
                                                    MachineInstr &MI,
                                                    unsigned Index) {
  unsigned LitOffset = MI.getNumOperands() - 1;
  MachineOperand &Lit = getLiteralOperand(MI, LitOffset);

  std::random_device seed_gen;
  std::mt19937_64 mt(seed_gen());

  uint64_t Rnd = mt();
  uint64_t Imm = Lit.getImm();
  // replace literal operand by rnd
  MI.RemoveOperand(LitOffset);
  MachineOperand OpRnd = MachineOperand::CreateImm(Rnd);
  MI.addOperand(OpRnd);

  buildXor(MI, Index, Imm ^ Rnd);
}
