#! python2
#coding: utf-8
''' 
'''
import os
import re
import sys
import ctypes
import collections
import ConfigParser

import sip
sip.setapi('QString', 2)
from PyQt4 import QtCore, QtGui, uic


Function = collections.namedtuple('Function','start end callees callers')   # callees: 此函数调用的函数
                                                                            #   address1 callee1，此函数在address1处调用了callee1
                                                                            # callers: 调用此函数的函数
                                                                            #   caller1 address1，caller1在address1处调用了此函数

'''
class HFView(QtGui.QWidget):
    def __init__(self, parent=None):
        super(HFView, self).__init__(parent)
        
        uic.loadUi('HFView.ui', self)
'''
from HFView_UI import Ui_HFView
class HFView(QtGui.QWidget, Ui_HFView):
    def __init__(self, parent=None):
        super(HFView, self).__init__(parent)
        
        self.setupUi(self)

        self.initSetting()

        self.CPURegs = collections.OrderedDict([
            ('R0',        0),   # 0, jlink.JLINKARM_ReadReg index
            ('R1',        0),
            ('R2',        0),
            ('R3',        0),
            ('R4',        0),
            ('R5',        0),
            ('R6',        0),
            ('R7',        0),
            ('R8',        0),
            ('R9',        0),
            ('R10',       0),
            ('R11',       0),
            ('R12',       0),
            ('R13(SP)',   0),
            ('R14(LR)',   0),
            ('R15(PC)',   0),
            ('XPSR',      0),   # 16
            ('MSP',       0),
            ('PSP',       0),
            ('RAZ',       0),
            ('CFBP',      0),
            ('APSR',      0),
            ('EPSR',      0),
            ('IPSR',      0),
            ('PRIMASK',   0),
            ('BASEPRI',   0),
            ('FAULTMASK', 0),
            ('CONTROL',   0),   # 27
        ])
        
    def initSetting(self):
        if not os.path.exists('setting.ini'):
            open('setting.ini', 'w')
        
        self.conf = ConfigParser.ConfigParser()
        self.conf.read('setting.ini')
        
        if not self.conf.has_section('globals'):
            self.conf.add_section('globals')
            self.conf.set('globals', 'dllpath', '')
            self.conf.set('globals', 'dispath', '[]')
        self.linDLL.setText(self.conf.get('globals', 'dllpath').decode('gbk'))
        for path in eval(self.conf.get('globals', 'dispath')): self.cmbDis.insertItem(10, path)
    
    @QtCore.pyqtSlot()
    def on_btnDLL_clicked(self):
        path = QtGui.QFileDialog.getOpenFileName(caption=u'JLinkARM.dll路径', filter=u'动态链接库文件 (*.dll)', directory=self.linDLL.text())
        if path != '':
            self.linDLL.setText(path)
    
    @QtCore.pyqtSlot()
    def on_btnDis_clicked(self):
        path = QtGui.QFileDialog.getOpenFileName(caption=u'反汇编文件路径', filter=u'disassembler (*.dis *.asm *.txt)', directory=self.cmbDis.currentText())
        if path != '':
            self.cmbDis.insertItem(0, path)
            self.cmbDis.setCurrentIndex(0)

    @QtCore.pyqtSlot(str)
    def on_cmbDis_currentIndexChanged(self, txt):
        self.Functions = collections.OrderedDict()

    def parseDis(self, path):
        with open(path, 'r') as f:
            txt = f.read()

            self.Functions = collections.OrderedDict()
            self.parseDis_MDK(txt)
            if not self.Functions:
                self.parseDis_GCC(txt)
                if not self.Functions:
                    return              # disassembler parse fail

        for name in self.Functions:
            for name2, func in self.Functions.iteritems():
                for addr, callee in func.callees:                           # name2调用的函数中有name
                    if name == callee:
                        self.Functions[name].callers.append((name2, addr))  # name的调用者中添加name2
                        # TODO: 如果name2中多处调用name，怎么处理
                        break

        for name, func in self.Functions.iteritems():
            print '\n%-030s @ 0x%08X - 0x%08X' %(name, func.start, func.end)
            for addr, name in func.callees:
                print '    0x%08X %s' %(addr, name)
        print '\n'
        for name, func in self.Functions.iteritems():
            print '\n%-030s called by:' %name
            for name, addr in func.callers:
                print '    %-030s @ 0x%08X' %(name, addr)

    def parseDis_MDK(self, txt):
        for match in re.finditer(r'\n    ([A-Za-z_][A-Za-z_0-9]*)\n(        (0x[0-9a-f]{8}):[\s\S]+?)(?=\n    [A-Za-z_\$])', txt):
            name, start, end = match.group(1), int(match.group(3), 16), int(match.group(3), 16)

            lastline = match.group(2).strip().split('\n')[-1]
            match2 = re.match(r'        (0x[0-9a-f]{8}):', lastline)
            if match2:
                end = int(match2.group(1), 16)

            self.Functions[name] = Function(start, end, [], [])

            for line in match.group(2).split('\n'):
                match2 = re.match(r'        (0x[0-9a-f]{8}):\s+[0-9a-f]{4,8}\s+\S+\s+B[L.W]*\s+([A-Za-z_][A-Za-z0-9_]*) ;', line)
                if match2:
                    address, callee = int(match2.group(1), 16), match2.group(2)
                    self.Functions[name].callees.append((address, callee))

    def parseDis_GCC(self, txt):
        for match in re.finditer(r'\n([0-9a-f]{8}) <([A-Za-z_][A-Za-z_0-9]*)>:([\s\S]+?)(?=\n\n)', txt):
            name, start, end = match.group(2), int(match.group(1), 16), int(match.group(1), 16)

            lastline = match.group(3).strip().split('\n')[-1]
            match2 = re.match(r'\s+([0-9a-f]{1,8}):\s+[0-9a-f]{4}', lastline)
            if match2:
                end = int(match2.group(1), 16)

            self.Functions[name] = Function(start, end, [], [])

            for line in match.group(3).split('\n'):
                match2 = re.match(r'\s+([0-9a-f]{1,8}):.+?bl\s+[0-9a-f]+\s<([A-Za-z_][A-Za-z0-9_]*)>', line)
                if match2:
                    address, callee = int(match2.group(1), 16), match2.group(2)
                    self.Functions[name].callees.append((address, callee))

    @QtCore.pyqtSlot()
    def on_btnRead_clicked(self):
        try:
            self.jlink = ctypes.cdll.LoadLibrary(self.linDLL.text())

            self.jlink.JLINKARM_Open()
            if not self.jlink.JLINKARM_IsOpen():
                raise Exception('No JLink connected')

            BUFF_LEN = 64
            err_buf = (ctypes.c_char * BUFF_LEN)()
            res = self.jlink.JLINKARM_ExecCommand('Device = Cortex-M0', err_buf, BUFF_LEN)

            self.jlink.JLINKARM_TIF_Select(1)
            self.jlink.JLINKARM_SetSpeed(4000)

            self.jlink.JLINKARM_Halt()
            for i, reg in enumerate(self.CPURegs):
                self.CPURegs[reg] = self.jlink.JLINKARM_ReadReg(i)
                if self.CPURegs[reg] < 0: self.CPURegs[reg] += 0x100000000  # 返回值int类型，若大于0x80000000则会变成负数
            self.CPURegs['CONTROL'] >>= 24  # J-Link Control Panel 中显示的也是移位前的

            self.txtMain.append('\nCPU Registers:')
            self.txtMain.append(
                'R0  : 0x%08X      R1  : 0x%08X      R2  : 0x%08X      R3  : 0x%08X\n'
                'R4  : 0x%08X      R5  : 0x%08X      R6  : 0x%08X      R7  : 0x%08X\n'
                'R8  : 0x%08X      R9  : 0x%08X      R10 : 0x%08X      R11 : 0x%08X\n'
                'R12 : 0x%08X      SP  : 0x%08X      LR  : 0x%08X      PC  : 0x%08X\n'
                'MSP : 0x%08X      PSP : 0x%08X\n'
                'XPSR: 0x%08X      APSR: 0x%08X      EPSR: 0x%08X      IPSR: 0x%08X\n'
                'CONTROL: 0x%02X (when Thread mode: %s, use %s)\n'
                'BASEPRI: 0x%02X         PRIMASK: %d            FAULTMASK: %d'
              %(self.CPURegs['R0'],     self.CPURegs['R1'],     self.CPURegs['R2'],     self.CPURegs['R3'],
                self.CPURegs['R4'],     self.CPURegs['R5'],     self.CPURegs['R6'],     self.CPURegs['R7'],
                self.CPURegs['R8'],     self.CPURegs['R9'],     self.CPURegs['R10'],    self.CPURegs['R11'],
                self.CPURegs['R12'],    self.CPURegs['R13(SP)'],self.CPURegs['R14(LR)'],self.CPURegs['R15(PC)'],
                self.CPURegs['MSP'],    self.CPURegs['PSP'],
                self.CPURegs['XPSR'],   self.CPURegs['APSR'],   self.CPURegs['EPSR'],   self.CPURegs['IPSR'],
                self.CPURegs['CONTROL'], 'unprivileged' if self.CPURegs['CONTROL']&1 else 'privileged', 'PSP' if self.CPURegs['CONTROL']&2 else 'MSP',
                self.CPURegs['BASEPRI'],self.CPURegs['PRIMASK'],self.CPURegs['FAULTMASK']
                ))
            
            if self.CPURegs['IPSR'] == 3:
                self.fault_diagnosis()

            if self.cmbStkSel.currentText() == 'Auto':
                if (self.CPURegs['R14(LR)'] >> 2) & 1 == 0:
                    self.Stack_SP = self.CPURegs['MSP']
                else:
                    self.Stack_SP = self.CPURegs['PSP']
            else:
                self.Stack_SP = self.CPURegs[self.cmbStkSel.currentText()]

            self.Stack_LEN = int(self.linStkSize.text())
            self.Stack_Mem = (ctypes.c_uint32 * self.Stack_LEN)()
            self.jlink.JLINKARM_ReadMemU32(self.Stack_SP, self.Stack_LEN, self.Stack_Mem, 0)
            self.jlink.JLINKARM_Close()

            self.txtMain.append('\nStack Content @ 0x%08X:' %self.Stack_SP)
            for i in range(self.Stack_LEN // 8):
                self.txtMain.append('%08X:  %08X %08X %08X %08X %08X %08X %08X %08X'
                    %(self.Stack_SP+i*8*4, self.Stack_Mem[i*8], self.Stack_Mem[i*8+1], self.Stack_Mem[i*8+2], self.Stack_Mem[i*8+3], self.Stack_Mem[i*8+4], self.Stack_Mem[i*8+5], self.Stack_Mem[i*8+6], self.Stack_Mem[i*8+7]))
            if self.Stack_LEN % 8:
                self.txtMain.append('%08X:  %s' %(self.Stack_SP+(self.Stack_LEN // 8)*8*4, ' '.join('%08X' %self.Stack_Mem[(self.Stack_LEN // 8)*8+i] for i in range(self.Stack_LEN % 8))))

        except Exception as e:
            self.txtMain.append('\nError:\n%s' %e)

    @QtCore.pyqtSlot()
    def on_btnParse_clicked(self):
        if not self.Functions:
            self.parseDis(self.cmbDis.currentText())
            if not self.Functions:
                self.txtMain.append('\nDisassembler parse fail!\n')
                return

            self.Program_Start = min([func.start for (name, func) in self.Functions.iteritems()])
            self.Program_End   = max([func.end   for (name, func) in self.Functions.iteritems()])
            print '\nProgram @ 0x%08X - 0x%08X' %(self.Program_Start, self.Program_End)

        self.on_btnRead_clicked()
        if self.CPURegs['IPSR'] != 3:
            self.txtMain.append('\nNot in HardFault\n')
            return

        self.CallStack, index = [], 0
        while index < self.Stack_LEN:
            if ((index <= self.Stack_LEN - 8) and
                (self.Program_Start <= self.Stack_Mem[index+5] <= self.Program_End and self.Stack_Mem[index+5]%2 == 1) and 
                (self.Program_Start <= self.Stack_Mem[index+6] <= self.Program_End and self.Stack_Mem[index+6]%2 == 0) and 
                ((self.Stack_Mem[index+7] >> 24) & 1 == 1)):    # 中断服务

                for name, func in self.Functions.iteritems():   # 找出中断压栈时正在执行的函数
                    if func.start <= self.Stack_Mem[index+6] <= func.end:
                        self.CallStack.append((self.Stack_Mem[index+6], name))
                        break
                else:
                    self.txtMain.append('\nCannot find the function be interrupted\n')
                    break

                index += 8

            elif index == 0:
                self.txtMain.append('\nPlease make sure the stack is an Exception Stack Frame\n')
                return

            else:                                               # 函数调用
                for name, addr in self.Functions[self.CallStack[-1][1]].callers: # 遍历函数的调用者，谁在栈内
                    if self.Stack_Mem[index] == addr + 4 + 1:   # 存入LR的值是函数调用指令地址 + 4，然后地址低位为1
                        self.CallStack.append((self.Stack_Mem[index], name))
                        break

                index += 1
                
        self.txtMain.append('\nCall Stack:')
        for addr, name in self.CallStack:
            self.txtMain.append('0x%08X  %s' %(addr, name))

    def fault_diagnosis(self):
        SCS_BASE  =  0xE000E000
        SCB_BASE  = (SCS_BASE + 0x0D00)

        SCB_CPUID = (SCB_BASE + 0x00)   # 
        SCB_CFSR  = (SCB_BASE + 0x28)   # Configurable Fault Status Register
        SCB_HFSR  = (SCB_BASE + 0x2C)   # HardFault Status Register
        SCB_DFSR  = (SCB_BASE + 0x30)   # Debug Fault Status Register
        SCB_MFAR  = (SCB_BASE + 0x34)   # MemManage Fault Address Register
        SCB_BFAR  = (SCB_BASE + 0x38)   # BusFault Address Register
        SCB_AFSR  = (SCB_BASE + 0x3C)   # Auxiliary Fault Status Register

        SCB_CPUID_PARTNO_Pos        =  4
        SCB_CPUID_PARTNO_Msk        = (0xFFF << SCB_CPUID_PARTNO_Pos)
        SCB_CPUID_ARCHITECTURE_Pos  = 16
        SCB_CPUID_ARCHITECTURE_Msk  = (0xF   << SCB_CPUID_ARCHITECTURE_Pos)

        # HFSR: HardFault Status Register
        SCB_HFSR_VECTTBL_Pos        =  1        # Indicates hard fault is caused by failed vector fetch
        SCB_HFSR_VECTTBL_Msk        = (1 << SCB_HFSR_VECTTBL_Pos)
        SCB_HFSR_FORCED_Pos         = 30        # Indicates hard fault is taken because of bus fault/memory management fault/usage fault
        SCB_HFSR_FORCED_Msk         = (1 << SCB_HFSR_FORCED_Pos)
        SCB_HFSR_DEBUGEVT_Pos       = 31        # Indicates hard fault is triggered by debug event
        SCB_HFSR_DEBUGEVT_Msk       = (1 << SCB_HFSR_DEBUGEVT_Pos)

        # MFSR: MemManage Fault Status Register
        SCB_MFSR_IACCVIOL_Pos       = 0         # Instruction access violation
        SCB_MFSR_IACCVIOL_Msk       = (1 << SCB_MFSR_IACCVIOL_Pos)
        SCB_MFSR_DACCVIOL_Pos       = 1         # Data access violation
        SCB_MFSR_DACCVIOL_Msk       = (1 << SCB_MFSR_DACCVIOL_Pos)
        SCB_MFSR_MUNSTKERR_Pos      = 3         # Unstacking error
        SCB_MFSR_MUNSTKERR_Msk      = (1 << SCB_MFSR_MUNSTKERR_Pos)
        SCB_MFSR_MSTKERR_Pos        = 4         # Stacking error
        SCB_MFSR_MSTKERR_Msk        = (1 << SCB_MFSR_MSTKERR_Pos)
        SCB_MFSR_MMARVALID_Pos      = 7         # Indicates the MMAR is valid
        SCB_MFSR_MMARVALID_Msk      = (1 << SCB_MFSR_MMARVALID_Pos)

        # BFSR: Bus Fault Status Register
        SCB_BFSR_IBUSERR_Pos        = 8         # Instruction access violation
        SCB_BFSR_IBUSERR_Msk        = (1 << SCB_BFSR_IBUSERR_Pos)
        SCB_BFSR_PRECISERR_Pos      = 9         # Precise data access violation
        SCB_BFSR_PRECISERR_Msk      = (1 << SCB_BFSR_PRECISERR_Pos)
        SCB_BFSR_IMPREISERR_Pos     = 10        # Imprecise data access violation
        SCB_BFSR_IMPREISERR_Msk     = (1 << SCB_BFSR_IMPREISERR_Pos)
        SCB_BFSR_UNSTKERR_Pos       = 11        # Unstacking error
        SCB_BFSR_UNSTKERR_Msk       = (1 << SCB_BFSR_UNSTKERR_Pos)
        SCB_BFSR_STKERR_Pos         = 12        # Stacking error
        SCB_BFSR_STKERR_Msk         = (1 << SCB_BFSR_STKERR_Pos)
        SCB_BFSR_BFARVALID_Pos      = 15        # Indicates BFAR is valid
        SCB_BFSR_BFARVALID_Msk      = (1 << SCB_BFSR_BFARVALID_Pos)

        # UFSR: Usage Fault Status Register
        SCB_UFSR_UNDEFINSTR_Pos     = 16        # Attempts to execute an undefined instruction
        SCB_UFSR_UNDEFINSTR_Msk     = (1 << SCB_UFSR_UNDEFINSTR_Pos)
        SCB_UFSR_INVSTATE_Pos       = 17        # Attempts to switch to an invalid state (e.g., ARM)
        SCB_UFSR_INVSTATE_Msk       = (1 << SCB_UFSR_INVSTATE_Pos)
        SCB_UFSR_INVPC_Pos          = 18        # Attempts to do an exception with a bad value in the EXC_RETURN number
        SCB_UFSR_INVPC_Msk          = (1 << SCB_UFSR_INVPC_Pos)
        SCB_UFSR_NOCP_Pos           = 19        # Attempts to execute a coprocessor instruction
        SCB_UFSR_NOCP_Msk           = (1 << SCB_UFSR_NOCP_Pos)
        SCB_UFSR_UNALIGNED_Pos      = 24        # Indicates that an unaligned access fault has taken place
        SCB_UFSR_UNALIGNED_Msk      = (1 << SCB_UFSR_UNALIGNED_Pos)
        SCB_UFSR_DIVBYZERO0_Pos     = 25        # Indicates a divide by zero has taken place (can be set only if DIV_0_TRP is set)
        SCB_UFSR_DIVBYZERO0_Msk     = (1 << SCB_UFSR_DIVBYZERO0_Pos)

        buff = (ctypes.c_uint32 * 16)()
        self.jlink.JLINKARM_ReadMemU32(SCB_CPUID, 16, buff, 0)

        reg_CPUID, reg_CFSR, reg_HFSR, reg_MFAR, reg_BFAR = buff[0], buff[10], buff[11], buff[13], buff[14]

        if ((reg_CPUID & SCB_CPUID_PARTNO_Msk) >> SCB_CPUID_PARTNO_Pos) in [0xC20, 0xC60]: # Cortex-M0, Cortex-M0+
            return

        self.txtMain.append('')
        if (reg_HFSR & SCB_HFSR_VECTTBL_Msk):
            self.txtMain.append('hard fault is caused by failed vector fetch')
        elif (reg_HFSR & SCB_HFSR_FORCED_Msk):
            if (reg_CFSR & (0xFF << 0)):        # Memory Management Fault
                if (reg_CFSR & SCB_MFSR_IACCVIOL_Msk):
                    self.txtMain.append('Instruction access violation')
                if (reg_CFSR & SCB_MFSR_DACCVIOL_Msk):
                    self.txtMain.append('Data access violation')
                if (reg_CFSR & SCB_MFSR_MUNSTKERR_Msk):
                    self.txtMain.append('Unstacking error')
                if (reg_CFSR & SCB_MFSR_MSTKERR_Msk):
                    self.txtMain.append('Stacking error')
                if (reg_CFSR & SCB_MFSR_MMARVALID_Msk):
                    self.txtMain.append('SCB->MFAR = 0x%08X' %reg_MFAR)
            if (reg_CFSR & (0xFF << 8)):        # Bus Fault
                if (reg_CFSR & SCB_BFSR_IBUSERR_Msk):
                    self.txtMain.append('Instruction access violation')
                if (reg_CFSR & SCB_BFSR_PRECISERR_Msk):
                    self.txtMain.append('Precise data access violation')
                if (reg_CFSR & SCB_BFSR_IMPREISERR_Msk):
                    self.txtMain.append('Imprecise data access violation')
                if (reg_CFSR & SCB_BFSR_UNSTKERR_Msk):
                    self.txtMain.append('Unstacking error')
                if (reg_CFSR & SCB_BFSR_STKERR_Msk):
                    self.txtMain.append('Stacking error')
                if (reg_CFSR & SCB_BFSR_BFARVALID_Msk):
                    self.txtMain.append('SCB->BFAR = 0x%08X' %reg_BFAR)
            if (reg_CFSR & (0xFFFF << 16)):     # Usage Fault
                if (reg_CFSR & SCB_UFSR_UNDEFINSTR_Msk):
                    self.txtMain.append('Attempts to execute an undefined instruction')
                if (reg_CFSR & SCB_UFSR_INVSTATE_Msk):
                    self.txtMain.append('Attempts to switch to an invalid state (e.g., ARM)')
                if (reg_CFSR & SCB_UFSR_INVPC_Msk):
                    self.txtMain.append('Attempts to do an exception with a bad value in the EXC_RETURN number')
                if (reg_CFSR & SCB_UFSR_NOCP_Msk):
                    self.txtMain.append('Attempts to execute a coprocessor instruction')
                if (reg_CFSR & SCB_UFSR_UNALIGNED_Msk):
                    self.txtMain.append('an unaligned access fault has taken place')
                if (reg_CFSR & SCB_UFSR_DIVBYZERO0_Msk):
                    self.txtMain.append('a divide by zero has taken place (can be set only if DIV_0_TRP is set)')

    @QtCore.pyqtSlot()
    def on_btnClear_clicked(self):
        self.txtMain.clear()
    
    def closeEvent(self, evt):
        self.closed = True
        
        self.conf.set('globals', 'dllpath', self.linDLL.text().encode('gbk'))
        
        dispaths = [self.cmbDis.itemText(i) for i in range(self.cmbDis.count())]
        if self.cmbDis.currentIndex() not in [0, -1]: dispaths = [self.cmbDis.currentText()] + dispaths     # 将当前项置于最前
        dispaths = list(collections.OrderedDict.fromkeys(dispaths))                                         # 保留顺序去重
        self.conf.set('globals', 'dispath', repr(dispaths[:10]))

        self.conf.write(open('setting.ini', 'w'))
        

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    rtt = HFView()
    rtt.show()
    app.exec_()
