# 恶意软件(Malware)

## 类型

- 后门(backdoor)

  将自己嵌入到计算机中以使远程攻击者喝少或无权在任何相应的本地计算机上执行命令

- 僵尸网络(botnet)

  允许攻击者访问网络, 然而不是从一个远程攻击者那里接收命令, 而是从命令和控制服务器(command-and-control server)那里接收指令, 可以同时操控无限量的计算机

- 下载器(downloader)

  不是恶意代码, 但他的唯一目的是安装其他恶意软件, 下载的其他软件控制系统

- rootkit

  隐藏自身的存在和用户的其他恶意软件, 使得它很难被发现, rootkit可以操纵将自己的IP隐藏在一个IP scan, 这样用户就不会知道他们对僵尸网络或者其他远程计算机有着直接的socket

# X86

## 介绍

x86是基于Intel 8086处理器的**小端**体系结构, 一般来说, 可以在两种操作模式下运行: **实模式和保护模式**:

- 实模式:处理器刚刚上电后只支持16位指令集的状态
- 保护模式: 处理器支持虚拟内存, 分页以及其他功能, 也是运行当前OS的状态

此体系结构的64位拓展称为x64或x86-64



x86通过**环级别**(ring level)的抽象来支持特权隔离, 其中处理器支持4中特权级别, 编号从0到3

<img src="assets/image-20250219142339921.png" alt="image-20250219142339921" style="zoom:50%;" />

RING的设计是将系统权限与进程分离, 使之能够让OS更好的管理当前的系统资源, 使系统更加稳定

## 寄存器

### 通用寄存器

运行于保护模式下的x86有8个32位**通用寄存器**(General Purpose Register, GPR), 指令指针存储在EIP中, 其他的GPR用途:

| 寄存器 | 用途                   |
| ------ | ---------------------- |
| ECX    | 循环计数               |
| EDX    | 存放整数除法产生的余数 |
| ESI    | 字符串/内存操作的源    |
| EDI    | 字符串/内存操作的目的  |
| EBP    | 帧寄存器               |
| ESP    | 栈指针                 |



### 特定模型寄存器

Model-Specific Register, MSR. 每个MSR用名字和一个32位数字标识, 通过RDMSR/WRMSR指令读写, 并且只有RING0级别的代码才能访问此类寄存器, 作用是存储特殊的技术或者实现底层功能(如SYSENTRY指令会将执行跳转到IA32_SYSENTRY_EIP MSR(0X176)存储的地址, 即OS的系统调用处理函数

## 指令集

数据移动的5种方式:

- 立即数$$\rightarrow$$寄存器
- 寄存器$$\rightarrow$$寄存器
- 立即数$$\rightarrow$$内存
- 内存$$\rightarrow$$寄存器(或反向)
- 内存$$\rightarrow$$内存

其中**内存$$\rightarrow$$内存**是x86独有, ARM只支持通过加载/存储指令从内存读写, 而x86可以直接访问内存; 并且x86使用变长指令(1-15Bytes), 而ARM的指令只能是2B或4B

## 语法

x86的汇编代码有两种记法: Intel和AT&T, 语法不同, 语义相同, 区别如下:

- AT&T在寄存器名前加前缀`%`, 立即数加前缀`$`, 16进制前加`0x`, 而Intel不加前缀
- AT&T加入了指示指令宽度的**后缀**(如`movl`(长整形), `movb`(字节)等)
- AT&T把源操作数放在目标操作数之前, 而Intel则相反

具体差别例子如下:

`Intel`:

```assembly
mov ecx, AABBCCDDh
mov ecx, [eax]
mov ecx, eax
```

`AT&T`:

```assembly
movl $0xAABBCCDD, %ecx
movl (%eax), %ecx
movl %eax, %ecx
```

### lea与mov的区别

- `mov`: (**数据传送指令**)

  在寄存器或内存之间传送数据, 将源操作数的值**复制**到目标操作数, 不会改变源操作数的值

- `lea`: (**加载有效地址**)

  `lea`会计算一个由一个或者多个寄存器或内存地址组成的复杂表达式的结果, 并将结果(有效地址)存储到目标寄存器中, 而**不会去访问或修改该地址处的内存内容**

源代码:

```c
#include <stdio.h>

int var_ele(long n, int A[n][n], long i, long j)
{
    return 1;
}

int main()
{
    int A[][3] = {{1,2,3}, {1,2,3}, {1,2,3}};
    var_ele(3, A, 10, 10);
    return 0;
}
```

IDA反汇编结果:

```assembly
; Attributes: bp-based frame

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

var_30= dword ptr -30h
var_2C= dword ptr -2Ch
var_28= dword ptr -28h
var_24= dword ptr -24h
var_20= dword ptr -20h
var_1C= dword ptr -1Ch
var_18= dword ptr -18h
var_14= dword ptr -14h
var_10= dword ptr -10h

push    rbp
mov     rbp, rsp
sub     rsp, 50h
call    __main
mov     [rbp+var_30], 1
mov     [rbp+var_2C], 2
mov     [rbp+var_28], 3
mov     [rbp+var_24], 1
mov     [rbp+var_20], 2
mov     [rbp+var_1C], 3
mov     [rbp+var_18], 1
mov     [rbp+var_14], 2
mov     [rbp+var_10], 3
lea     rax, [rbp+var_30]
mov     r9d, 0Ah
mov     r8d, 0Ah
mov     rdx, rax
mov     ecx, 3
call    var_ele
mov     eax, 0
add     rsp, 50h
pop     rbp
retn
main endp
```

### SCAS和STOS

指令的粒度可以是1,2,4字节, `SCAS`隐式的把AL/AX/EAX的数值与地址为EDI的内存数值比较, 并根据EFFLAG中的`DF`标志位(方向标志位, 如果DF=0, 存储器地址自动增加, 串操作指令为自动增量指令)不同, EDI自动递增或递减, 常用于与`REP`前缀一起在一段缓存中寻找某字节,字或双字(`strlen()`). `STOS`是把AL/AX/EAX中的值写入EDI指向的内存中, 常用于把缓存初始化为常量值(如`memset()`)

### 算数运算

其中移动指令通常用于**运算强度简化**

- 乘法运算寄存器使用:

  | **被乘数** | **乘数**  | **乘积** |
  | ---------- | --------- | -------- |
  | AL         | reg/mem8  | AX       |
  | AX         | reg/mem16 | DX:AX    |
  | EAX        | reg/mem32 | EDX:EAX  |

- 除法运算寄存器使用:

    | **被除数** | **除数**  | **商** | **余数** |
    | ---------- | --------- | ------ | -------- |
    | AX         | reg/mem8  | AL     | AH       |
    | DX:AX      | reg/mem16 | AX     | DX       |
    | EDX:EAX    | reg/mem32 | EAX    | EDX      |

- UMUL(有符号除法)的三种形式:

  - `IMUL reg/mem`: 与MUL相同
  - `IMUL reg1, reg2/mem` : reg1 = reg1 * reg2/mem
  - `IMUL reg1, reg2/mem, imm`: reg1 = reg2 * imm

### 栈操作

OS从RING3切换到RING0时, 要把状态信息保存在栈上. x86的栈是ESP指向的一段连续的内存区域, 向下增长. PUSH会递减ESP, 然后把数据写入ESP指向的位置; POP会读出ESP指向的位置的数据并递增ESP(默认递增/减的大小为4, 因为OS要求栈双字对其)

CALL指令:

- 把返回地址压栈(紧接着CALL指令的下一个地址)压栈
- 修改EIP为调用目标地址, 这样就把控制权转给了调用目标, 然后从调用目标继续进行

ERT指令: 把存储在栈的地址出栈道EIP, 然后传递控制给它

#### 调用惯例

Calling Convention, 是编译器在函数调用时遵循的规则, 用于定义函数参数的传递方式, 返回值的处理方式, 寄存器的使用和栈的管理 . 对于特定的系统是由程序二进制接口(ABI)定义的

常见的调用惯例:

<img src="assets/image-20250219204011435.png" alt="image-20250219204011435" style="zoom:67%;" />

其中FASTCALL是Microsoft 编译器支持的一种调用惯例, 规则详细如下:

- **前两个参数通过寄存器传递**：
  - 第一个参数通过 `ecx`（32 位）或 `rcx`（64 位）传递。
  - 第二个参数通过 `edx`（32 位）或 `rdx`（64 位）传递。
- **其余参数通过栈传递**。
- **返回值通过 `eax`（32 位）或 `rax`（64 位）返回**。
- **调用者负责清理栈**。

下面具体分析一个简单的代码:

```c
#include <stdio.h>

int 
__cdecl addme(short a, short b)
{
    return a+b;
}

int main()
{
    short x = 4;
    short y = 5;
    short sum = addme(x, y);
    return 0;
}
```

反编译结果如下:

main:

```assembly
; Attributes: bp-based frame

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

var_6= word ptr -6
var_4= word ptr -4
var_2= word ptr -2

push    rbp							; 保存调用者的栈帧基址
mov     rbp, rsp					; 设置当前函数的栈帧基址
sub     rsp, 30h					; 为局部变量分配栈空间（48 字节）
call    __main
mov     [rbp+var_2], 4				; 初始化两个局部变量
mov     [rbp+var_4], 5
movsx   edx, [rbp+var_4]			; 将 var_4 的值（5）符号扩展并加载到 edx 中
movsx   eax, [rbp+var_2]
mov     ecx, eax
call    addme						; 调用 addme 函数，参数通过 ecx 和 edx 传递
mov     [rbp+var_6], ax				; 保存返回值
mov     eax, 0
add     rsp, 30h					; 释放调用者栈帧基址
pop     rbp							; 恢复调用者的栈帧基址
retn
main endp
```

- 可以看出第二行的注释就说明了使用`__fastcall`调用惯例
- `__main`: 是 GCC 编译器在 `main` 函数开始时插入的初始化函数，用于初始化 C 运行时环境
- 根据 `__fastcall` 调用惯例：第一个参数通过 ecx 传递。第二个参数通过 edx 传递。

addme:

```assembly
; Attributes: bp-based frame

public addme
addme proc near

arg_0= word ptr  10h
arg_8= word ptr  18h

push    rbp
mov     rbp, rsp
mov     eax, edx			; 从在main函数传入的两个参数所存储的寄存器中取参数
mov     edx, ecx
mov     [rbp+arg_0], dx
mov     [rbp+arg_8], ax
movsx   edx, [rbp+arg_0]
movsx   eax, [rbp+arg_8]
add     eax, edx
pop     rbp
retn
addme endp
```

### 控制流

常见标志位:

- ZF: 结果是否为0
- SF: 符号标志, 设为当前结果的最高有效位
- CF: 借位标志, 当前结果是否需要借位, 对**无符号整数**才有效
- OF: 溢出标志, 当前结果是否超过了最大值, 对**有符号整数**有效



if-else的反汇编程序:

```c
#include <stdio.h>

int main()
{
    int* esi = NULL;

    if(*esi == 0){
        return 1;
    }
    return 0;
}
```

反汇编结果:

<img src="assets/image-20250219211550143.png" alt="image-20250219211550143" style="zoom:67%;" />

其中jnz为跳转指令

- 注: IDA切换流程图和反汇编代码快捷键为空格

## 系统机制

### 地址转换

物理内存以4KB为一个page, 在分页机制启动的情况下, 处理器执行的指令中使用的地址是虚拟地址, 而物理地址是处理器访问内存时使用的 实际内存地址, MMU(内存管理单元)在访问内存之前先透明的将虚拟地址转化为物理地址. 

虚拟地址看似是一个16进制数, 实际上对于MMU是**结构化**的, 对于支持PAE(物理地址拓展)的x86系统上虚拟地址划分为:(也即分页机制的多级页表, 在64位模式下（x86-64），分页机制通常使用 **4 级页表**, 第一级为PML4)

- PDPT(页目录指针表): 用于存储指向页目录（PD）的指针
- PD(页目录): 存储指向页表（PT）的指针
- PT(页表): 存储指向物理页的指针
- PTE(页表项): 是页表中的条目，用于存储物理页的基地址和相关的控制信息, 包含的字段如下:
  - 物理页基地址: 指向物理内存中的页
  - 标志位:
    - **P（Present）**：页是否在内存中。
    - **R/W（Read/Write）**：页是否可写。
    - **U/S（User/Supervisor）**：页是否可被用户程序访问。
    - **A（Accessed）**：页是否被访问过。
    - **D（Dirty）**：页是否被修改过

直接上图(32bit):

<img src="assets/image-20250219212633216.png" alt="image-20250219212633216" style="zoom:67%;" />

- ps: (64位)

  | 63-48 | 47-39 | 38-30 | 29-21 | 20-12 | 11-0   |
  | ----- | ----- | ----- | ----- | ----- | ------ |
  | Sign  | PML4  | PDPT  | PD    | PT    | Offset |

### 中断与异常

OS通过中断与异常实现系统调用

#### 中断

处理器通过数据总线(如PCIE, FireWire, USB)与外部设备连接, 当设备需要处理器处理时, 就会触发一个中断迫使处理器暂停当前的工作, 然后去处理这个设备的请求. 每个中断都关联一个(用于索引到一个**函数指针数组**的)数字, 当处理器收到中断时, 就会执行这个中断关联的数字索引到的函数, 然后恢复执行中断前的工作, 一般由硬件设备触发(即硬件中断, 是异步的过程)

#### 异常

两大类:

- 错误(fault):

  *可修正的异常*, 如缺页(处理器访问了地址有效, 但是当前的页已经被换出而导致数据不再主存), 这时处理器就会调用缺页异常处理程序来修正此错误, 然后**再执行**这条指令(这时就不会发生缺页异常了) 

- 陷阱(trap):

  执行某些特定类型的指令所产生的异常, 如SYSENTRY指令会使得处理器开始执行通用系统调用处理函数, 执行完毕后紧接着它的**下一条指令继续执行**

主要区别就是**运行从哪里恢复**

### 综合练习

#### 阅读汇编程序

阅读下面的汇编:

```assembly
sidt fword ptr [ebp-8]
mov eax, [ebp-6]
cmp eax, 80047400h
```



根据[Intel手册](https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-software-developers-manual-volume-2b-instruction-set-reference-m-u.html)中对SIDT的描述:

<img src="assets/image-20250220113235406.png" alt="image-20250220113235406" style="zoom:67%;" />

- 可以知道: SIDT写入IDT寄存器(Store Interrupt Descriptor Table Register, 包含256个中断向量, 每个表项为8B, 包含一个纸箱中断处理程序的指针, 一个段选择符和偏移量)一个6字节的内存区域, 高4B包含了IDT的基地址, 低2B存储表限制(非64bit, 64是8+2), 当中断/异常发生时, 处理器通过中断号索引到IDT, 调用表项中的处理程序, 直观的图如下:

  <img src="assets/273421-20210821214609592-856543503.png" alt="img" style="zoom:67%;" />

- 综上所述: 第二行是读出IDT的基地址

- 第三行的与特殊常数比较, 上网找是win xp的IDT基地址(我没找到)

#### x86实现函数

- `strlen()`:

  ```assembly
  strlen:
  	push ebp			; 保存基址指针
  	mov ebp, esp		; 设置新的基址指针
      push esi			; 保存ESI寄存器
      mov esi, [ebp+8]	; 获取字符串地址(第一个参数)
      xor eax, eax		; 将eax清零, 存储字符串长度
      
  strlen_loop:
  	mov cl, [esi]		; 将ESI指向的字符加载到CL寄存器
  	test cl, cl			; 查看字符串是否结束
  	jz strlen_done		
  	inc eax				; 计数器+1
  	inc esi				; 移动下一个字符
  	jmp strlen_loop
  	
  strlen_done:
  	pop esi
  	pop ebp
  	ret					; 返回, 其中EAX中存储字符串长度
  ```



### x64

x64寄存器组有18个64位GPR(通用寄存器), 前缀为R为64位寄存器

#### rip相对寻址

允许指令引用数据时使用相对于RIP(Instruction Pointer Register, 存储下一条将要执行的指令的内存地址, 在32位称为EIP)的地址, 如`lea rax, [rip+offset]`, 可以方便的访问当前指令附近的变量或者数据, 而不需要显示的计算绝对地址

#### 规范地址

当前的Intel处理器只使用48位地址空间, 所以剩下的16位高有效位都是0或1, 此时称为**规范地址**, 如果代码试图解引用一个非规范地址, 就会触发系统异常





## ARM

arm(Advanced RISC Machine)是RISC体系结构, 与x86相比, **指令集很小**, 但是提供的**通用寄存器很多**, 并且**指令宽度固定**(16/32bits), 内存访问模式是**加载-存储模式**, 就需要操作数据时需要先把他从内存加载到寄存器中, 递增, 然后再存储(即使用了3条指令: 加载, 递增, 存储), 所以逆向工程中代码量更大

在arm中, 有8种不同级别的特权模式:

- **用户模式（User Mode, USR）**：
  - 用于运行应用程序。
  - 权限最低，无法直接访问硬件或执行特权指令。
- **快速中断模式（FIQ Mode, FIQ）**：
  - 用于处理高速中断（Fast Interrupt Request）。
  - 有独立的寄存器组（R8-R14），以减少中断处理时的上下文切换开销。
- **普通中断模式（IRQ Mode, IRQ）**：
  - 用于处理普通中断（Interrupt Request）。
  - 与 FIQ 模式相比，IRQ 模式的优先级较低。
- **管理模式（Supervisor Mode, SVC）**：
  - 用于运行操作系统内核。
  - 当处理器复位或执行 `SWI`（软件中断）指令时，会进入此模式。
- **中止模式（Abort Mode, ABT）**：
  - 用于处理内存访问异常（如访问无效内存地址）。
  - 在数据或指令预取失败时进入此模式。
- **未定义模式（Undefined Mode, UND）**：
  - 用于处理未定义指令异常。
  - 当处理器遇到未定义的指令时，会进入此模式。
- **系统模式（System Mode, SYS）**：
  - 一种特殊的特权模式，与用户模式共享寄存器。
  - 用于运行操作系统的特权任务。
- **监控模式（Monitor Mode, MON）**：
  - 用于安全扩展（TrustZone 技术）。
  - 在安全世界和非安全世界之间切换时使用。

USR模式下运行的代码不同修改系统寄存器, 若要修改通常需要在SVC模式下才能修改, 多数的OS内核模式会运行于SVC, 用户模式运行于USR

### arm特性

#### 运行状态

在x86上可以交替运行在32位和64位模式, 在ARM中的两种状态为: **ARM和Thumb**模式, 两者*只决定指令集而不是特权模式*, ARM为32位宽, 而Thumb通常为16位, 两者执行的因素为:

- 通过BX和BLX指令进行分支跳转是, 如果目标寄存器的最低有效位为1, 切换到Thumb模式
- 当前程序状态寄存器(CPSR)中的T标志位被置起, 处在Thumb模式

默认核心进入arm状态并保持, 直到隐式或显式切换, 较新的OS使用Thumb代码是为了**获得更高的代码密度**

#### 条件执行

arm还支持**条件执行**, 指令中编码了算数条件, 只有在条件满足的时候指令才会被执行, 而x86则是每条指令无条件执行. 条件执行减少了分支指令, 也减少了被执行指令的数目

#### 桶式移位器

可以把多条指令压缩为1条, 即算数指令可以**嵌入到**某些指令中, 如执行:`R1 = R0 * 2`可以这样表示:`MOV R1, R0, LSL #1`(把乘法也放在MOV中)

### 寄存器

定义了16个32位通用寄存器, R0~R15, 通常只使用前13个作为通用寄存器, 最后三个特殊的:

- R13: 栈指针(SP), 等价于X86的ESP/RSP
- R14: 连接寄存器(LR), 保存函数调用的返回地址, 如BL总是在分支跳转到目标地址之前把返回地址保存在LR中, 而x86是将返回地址保存在栈上, 故无响应的寄存器
- R15: 程序计数器(PC), 在ARM状态下执行时当前指令地址增8, 而在Thumb将当前指令地址加4,  类似于X86的EIP/RIP(总是指向下一条执行指令的地址)

ARM把当前执行的转台信息保存在当前程序状态寄存器中(CPSR), 类似于x86的EFLAGS/RFLAG

### 协处理器

支持额外的指令和系统级设置, arm共有16个协处理器, 即CP0~CP15, 前13个是可选的或是保留的,  CP10, CO11常用于提供浮点数,向量和NEON支持(提供了单指令多数据指令集(SIMD), 常用于多媒体应用程序); CP14,CP15用于调试和系统设置, CP15称为**系统控制协处理器**, 保留系统设置, 管理内存、缓存、MMU（内存管理单元）等系统级功能

举个指令例子:`MRC p15, 0, R0, c1, c0, 0` 表示将 CP15 的寄存器 C1 的值移动到 ARM 寄存器 R0。

- `MRC`（Move to ARM Register from Coprocessor）

### 指令集

