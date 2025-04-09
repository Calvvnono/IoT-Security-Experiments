## 1

**一、 实验任务 (Experiment Tasks)**

1.  **环境搭建与配置:**
    *   安装 PBC 库及其依赖 GMP。
    *   配置 C++ 开发环境以链接 PBC 库。
    *   选择并初始化一个 Type A 的双线性配对 (`pairing_t`)。

2.  **实现访问树 (Access Tree) 数据结构:**
    *   设计一个 C++ 类或结构体来表示访问树的节点。
    *   节点应能存储：
        *   是叶节点还是内部节点。
        *   父节点指针/引用 (`parent(x)` 的概念)。
        *   子节点列表/数组（及其数量 `num_x`）。
        *   子节点的索引 (`index(x)`)。
        *   阈值 `k_x` (内部节点)。
        *   关联的属性 `att(x)` (叶节点)。
    *   实现访问树的满足条件检查函数 `T_x(γ)`（递归逻辑）。

3.  **实现 Setup 算法:**
    *   **输入:** 属性全集 U (可以隐式定义或从配置读取)。
    *   **过程:**
        *   为每个属性 `i` in U 选择随机 `t_i` in Zp。
        *   选择随机 `y` in Zp。
        *   获取 G1 的生成元 `g`。
        *   计算 `T_i = g^{t_i}` for all `i` in U。
        *   计算 `Y = e(g, g)^y`。
    *   **输出:**
        *   公开参数 PK: `{g, T_1, ..., T_{|U|}, Y}` (G1 和 GT 元素)。
        *   主密钥 MK: `{t_1, ..., t_{|U|}, y}` (Zp 元素)。

4.  **实现 Key Generation (KeyGen) 算法:**
    *   **输入:** 访问树 T，主密钥 MK。
    *   **过程:**
        *   **多项式分配:** 实现一个递归函数，从根节点 `r` 开始遍历访问树：
            *   为根节点 `r`：设置 `q_r(0) = y`，随机选择 `d_r = k_r - 1` 个 Zp 元素定义多项式 `q_r`。
            *   为非根非叶节点 `x`：设置 `q_x(0) = q_{parent(x)}(index(x))`，随机选择 `d_x = k_x - 1` 个 Zp 元素定义多项式 `q_x`。
            *   为叶节点 `x`：设置 `q_x(0) = q_{parent(x)}(index(x))` (多项式 `q_x` 为常数)。
        *   **密钥分量计算:** 对树中的每个叶节点 `x`：
            *   获取其属性 `i = att(x)`。
            *   计算 `D_x = g^{q_x(0) / t_i}` (注意是除法，即乘以 `t_i` 的逆元)。
    *   **输出:** 解密密钥 D: `{D_x}` (所有叶节点对应的 G1 元素集合)。

5.  **实现 Encryption (Encrypt) 算法:**
    *   **输入:** 消息 M (属于 GT，*手册原文 E'=MY^s 暗示 M 和 E' 都在 GT*), 属性集合 `γ` (字符串或其他可区分的属性表示), 公开参数 PK。
    *   **过程:**
        *   选择一个随机数 `s` in Zp。
        *   计算 `E' = M * Y^s`。
        *   对于 `γ` 中的每一个属性 `i`，计算 `E_i = T_i^s`。
    *   **输出:** 密文 E: `(γ, E', {E_i}_{i ∈ γ})`。

6.  **实现 Decryption (Decrypt) 算法:**
    *   **输入:** 密文 E `(γ, E', {E_i}_{i ∈ γ})`, 解密密钥 D (包含与访问树 T 对应的 `{D_x}`), 访问树 T。
    *   **过程:** 实现递归函数 `DecryptNode(E, D, x)`：
        *   **叶节点 x:**
            *   令 `i = att(x)`。
            *   如果 `i` 属于密文属性集 `γ`：计算 `e(D_x, E_i)` 并返回结果 (GT 元素)。
            *   否则：返回 `⊥` (表示无法解密或无效，可以用一个特殊值或标志)。
        *   **非叶节点 x:**
            *   对节点 `x` 的所有子节点 `z` 递归调用 `F_z = DecryptNode(E, D, z)`。
            *   检查返回非 `⊥` 结果的子节点数量，如果少于 `k_x`，则返回 `⊥`。
            *   选取 `k_x` 个返回有效结果 `F_z` 的子节点，构成集合 `S_x`。
            *   **拉格朗日插值:** 对 `S_x` 中的每个子节点 `z` (其索引为 `i = index(z)`)，计算拉格朗日系数 `Δ_{i, S'_x}(0)` (其中 `S'_x = {index(z) | z ∈ S_x}`)。
            *   计算 `F_x = Π_{z ∈ S_x} (F_z)^{Δ_{i, S'_x}(0)}` (在 GT 群上进行幂运算和乘法)。
            *   返回 `F_x`。
        *   **最终解密:** 调用 `DecryptNode(E, D, r)` (r 是树的根节点)，得到结果 `A = e(g, g)^{ys} = Y^s`。
        *   计算 `M = E' / A` (即 `E' * A^{-1}`)。
    *   **输出:** 原始消息 M (GT 元素)。

7.  **实现拉格朗日系数计算:**
    *   实现一个辅助函数，计算给定点集 `S` 和索引 `i` 在点 0 处的拉格朗日系数 `Δ_{i, S}(0)`。这涉及在 Zp 域内的加、减、乘和求逆运算。

8.  **测试与验证:**
    *   设计测试用例，包括不同的访问树结构和属性集。
    *   创建匹配和不匹配的密钥/密文对。
    *   验证加密和解密过程是否能正确恢复消息（仅当密钥策略满足密文属性时）。
    *   验证 `T_x(γ)` 函数的正确性。

**二、 实现思路 (Implementation Approach using C++ and PBC)**

1.  **环境与初始化:**
    *   包含头文件 `<pbc.h>`。
    *   使用 `pairing_init_set_str` 或 `pairing_init_set_buf` 加载 Type A 曲线参数来初始化 `pairing_t` 变量。确保使用手册推荐的参数（rbit=160, qbit=512）。
    *   使用 `element_init_G1`, `element_init_G2` (如果需要), `element_init_GT`, `element_init_Zr` 初始化所需的 `element_t` 变量。 **注意:** 手册提到 M 在 G2，但加密公式和解密过程更符合 M 在 GT 的情况。你需要确认这一点，如果 M 真在 G2，则加密和解密公式需要调整或使用不同的配对（如 `e: G1 x G2 -> GT`，PBC 支持 Type A 对称配对 `G1=G2` 和非对称配对）。这里假设 M 在 GT。

2.  **访问树表示:**
    *   使用 C++ `struct` 或 `class` `TreeNode`。包含 `bool is_leaf`, `int kx`, `int num_children`, `std::string attribute` (或 `int` ID), `int index_in_parent`, `TreeNode* parent`, `std::vector<TreeNode*> children`。
    *   实现 `check_satisfy(const std::set<std::string>& gamma)` 方法来实现 `T_x(γ)` 逻辑。

3.  **Setup 实现:**
    *   使用 `element_random(t_i)` 和 `element_random(y)` 生成 Zp 元素。
    *   使用 `pairing_get_g1(g, pairing)` 获取生成元 `g` (如果参数未直接提供)。
    *   使用 `element_pow_zn(T_i, g, t_i)` 计算 G1 元素。
    *   使用 `element_pairing(temp_gt, g, g)` 和 `element_pow_zn(Y, temp_gt, y)` 计算 `Y`。
    *   将 PK 和 MK 的 `element_t` 存储在合适的 C++ 结构中（例如 `PublicKey`, `MasterKey` 类）。记得要管理 `element_t` 的生命周期。

4.  **Key Generation 实现:**
    *   **多项式处理:** 不需要显式存储多项式的所有系数。递归函数的核心是计算 `q_x(0)` 和 `q_{parent(x)}(index(x))`。
        *   对于节点 `x`，需要存储/计算其多项式 `q_x` 在点 `0` 的值 `q_x(0)`。
        *   为定义多项式 `q_x`，需要生成 `d_x = k_x - 1` 个随机 Zp 元素（这些可以作为多项式在其他点的取值，或者直接作为系数，除了常数项）。
        *   计算 `q_{parent(x)}(index(x))` 需要知道父节点的多项式。这可以通过父节点的多项式系数或其在特定点的取值（包括 `0` 和其子节点的 `index`）来完成。
    *   **递归函数:** 设计一个递归函数 `assign_polynomials(TreeNode* node, element_t& parent_poly_eval_at_index, const MasterKey& mk)`。
        *   根节点：`parent_poly_eval_at_index` 设为 MK 中的 `y`。随机生成 `d_r` 个点定义 `q_r`。
        *   非根节点：`q_x(0)` 设置为传入的 `parent_poly_eval_at_index`。随机生成 `d_x` 个点定义 `q_x`。
        *   在递归调用子节点 `z` 时，需要计算 `q_x(index(z))` 并作为参数传递。
    *   **密钥计算:** 在递归到达叶节点 `x` 时：
        *   获取 `q_x(0)` (Zp 元素)。
        *   获取对应的 `t_i` (Zp 元素) from MK。
        *   计算 `t_i` 的逆元 `inv_ti` using `element_invert(inv_ti, t_i)`。
        *   计算指数 `exp = q_x(0) * inv_ti` using `element_mul(exp, qx0_zr, inv_ti)`。
        *   计算 `D_x = g^exp` using `element_pow_zn(Dx, g, exp)`。
    *   将所有 `D_x` (G1 元素) 存储在 `SecretKey` 结构中 (例如 `std::map<std::string, element_t>`)。

5.  **Encryption 实现:**
    *   用 `element_random(s)` 生成 `s`。
    *   计算 `Y^s` 使用 `element_pow_zn`。
    *   计算 `E' = M * Y^s` 使用 `element_mul` (在 GT 上)。
    *   遍历属性集 `γ`，对每个属性 `i`，从 PK 中获取 `T_i`，计算 `E_i = T_i^s` 使用 `element_pow_zn`。
    *   将 `γ`, `E'`, 和 `{E_i}` 存储在 `Ciphertext` 结构中。

6.  **Decryption 实现:**
    *   **递归函数 `DecryptNode`:**
        *   参数需要传递 `Ciphertext`, `SecretKey`, `TreeNode* node`。
        *   **叶节点:** 查找 `att(x)` 是否在 `E.gamma` 中。如果是，从 `D` 中获取 `D_x`，从 `E` 中获取对应的 `E_i`。计算 `pairing_apply(result_gt, Dx, Ei)`。返回 `result_gt`。否则返回表示 `⊥` 的特殊 `element_t` 或状态。
        *   **非叶节点:**
            *   创建一个 `std::vector<std::pair<int, element_t>>` 来存储子节点 `z` 的索引 `index(z)` 和有效的递归结果 `F_z`。
            *   遍历 `node->children`，递归调用 `DecryptNode`。如果结果有效，存入上述 vector。
            *   检查 vector 大小是否 `>= node->kx`。如果否，返回 `⊥`。
            *   从 vector 中选择 `node->kx` 个结果，构成集合 `S_x`（包含索引和 `F_z`）。
            *   **拉格朗日插值:**
                *   获取 `S_x` 中所有子节点的索引 `i = index(z)`，构成集合 `S'_x`。
                *   对 `S_x` 中的每个 `(i, F_z)` 对：
                    *   调用拉格朗日系数计算函数 `calculate_lagrange(delta_i, i, S'_x)` 得到 `delta_i` (Zp 元素)。
                    *   计算 `term_i = (F_z)^{delta_i}` 使用 `element_pow_zn` (在 GT 上)。
                *   计算最终结果 `F_x = Π term_i` 使用 `element_mul` (在 GT 上)。
            *   返回 `F_x`。
    *   **最终解密:** 调用 `DecryptNode` 获取 `A = Y^s`。计算 `A` 的逆元 `inv_A` using `element_invert(inv_A, A)`。计算 `M = E' * inv_A` using `element_mul(M, E_prime, inv_A)`。

7.  **拉格朗日系数计算 `Δ_{i, S}(0)`:**
    *   函数 `calculate_lagrange(element_t& result, int i, const std::vector<int>& S)`。
    *   `result` 初始化为 1 (in Zp)。
    *   遍历 `S` 中的 `j` (其中 `j != i`)：
        *   计算分子 `0 - j = -j` (Zp 元素)。
        *   计算分母 `i - j` (Zp 元素)。
        *   计算分母的逆元 `inv_denom`。
        *   计算 `term = (-j) * inv_denom`。
        *   更新 `result = result * term`。
    *   使用 `element_set_si`, `element_sub`, `element_invert`, `element_mul` in Zp。

8.  **内存管理:**
    *   **非常重要:** 对于每一个 `element_init_*`，必须在 `element_t` 变量不再需要时调用相应的 `element_clear` 来释放内存。在 C++ 中，RAII (Resource Acquisition Is Initialization) 模式是管理 `element_t` 的好方法，可以创建一个包装类，其构造函数调用 `element_init_*`，析构函数调用 `element_clear`。
    *   `pairing_clear` 在程序结束时调用。

9.  **数据结构:**
    *   使用 C++ `struct` 或 `class` 来组织 PK, MK, SK (密钥 D), Ciphertext (密文 E)。这些结构内部包含 `element_t` 成员或存储 `element_t` 的容器（如 `std::vector`, `std::map`）。确保这些结构正确处理其 `element_t` 成员的初始化和清理。

---

## 2

**一、 详细的准备工作 (中文)**

在编译和运行 `kp_abe.cpp` 代码之前，您需要确保您的系统（通常是 Linux 环境，如 Ubuntu、Debian、Fedora、CentOS 等）已安装以下必要的库和工具：

1. **C++ 编译器 (g++)**: 大多数 Linux 发行版会自带或可以通过包管理器轻松安装。

   * **Debian/Ubuntu**:

     ```bash
     sudo apt update
     sudo apt install build-essential
     ```

     (`build-essential` 通常包含 g++, make 等开发工具)

2. **GMP (GNU Multiple Precision Arithmetic Library)**: PBC 库依赖于 GMP 进行大数运算。需要安装开发包（包含头文件和库）。

   * **Debian/Ubuntu**:

     ```bash
     sudo apt install libgmp-dev
     ```

3. **OpenSSL 开发库**: 代码中使用了 OpenSSL 的随机数生成 (`RAND_bytes` 可能被 PBC 内部调用，或者为了更好的随机性保证而包含，链接时需要 `-lcrypto`)。

   * **Debian/Ubuntu**:

     ```bash
     sudo apt install libssl-dev
     ```

4. **PBC (Pairing-Based Cryptography) Library**: 这是核心库。通常需要从源码编译安装，因为它可能不在标准的发行版仓库中，或者版本较旧。

   * **获取源码**: 访问 PBC 官方网站: [https://crypto.stanford.edu/pbc/](https://crypto.stanford.edu/pbc/) 下载最新的源码包（通常是 `.tar.gz` 文件）。

   * **解压**:

     ```bash
     tar -zxvf pbc-0.5.14.tar.gz
     cd pbc-0.5.14/
     ```

   * **配置、编译和安装**:

     ```bash
     ./configure # sudo apt install flex/bison
     make
     sudo make install
     ```

     *   `configure` 脚本会自动检测 GMP 是否安装。如果遇到问题，请检查 `./configure --help` 或 PBC 的文档。
     *   `sudo make install` 通常会将库文件安装到 `/usr/local/lib`，头文件安装到 `/usr/local/include`。

   * **更新库缓存 (重要)**: 安装后，需要让系统知道新安装的库的位置。

     ```bash
     sudo ldconfig
     ```

     在某些系统上，如果库安装在非标准路径，您可能还需要将库路径添加到 `LD_LIBRARY_PATH` 环境变量中，但这通常在正确执行 `sudo make install` 和 `sudo ldconfig` 后不是必需的。

5. **保存代码和 Makefile**:

   *   将上面提供的 C++ 代码保存为 `kp_abe.cpp` 文件。
   *   将下面提供的 Makefile 内容保存为 `Makefile` 文件。
   *   确保这两个文件位于同一个目录下。

完成以上所有步骤后，您就可以在包含 `kp_abe.cpp` 和 `Makefile` 的目录下打开终端，执行 `make` 命令来编译代码了。

**二、 Makefile 文件**

```makefile
# Compiler and flags
CXX = g++
# Correct include path pointing to the 'pbc' subdirectory
CXXFLAGS = -std=c++17 -Wall -Wextra -g -I/usr/local/include/pbc

# Linker flags and libraries
# Library path is still correct
LDFLAGS = -L/usr/local/lib
LIBS = -lgmp -lpbc -lcrypto # Link against GMP, PBC, and OpenSSL crypto

# Source file and executable name - Double check your actual filename case
# Assuming kp_abe.cpp based on previous attempt, adjust if it's KP_ABE.cpp
SRC = kp_abe.cpp
EXEC = kp_abe

# Default target
all: $(EXEC)

# Rule to build the executable
$(EXEC): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(EXEC) $(SRC) $(LDFLAGS) $(LIBS)

# Clean up target
clean:
	rm -f $(EXEC)

# Phony targets
.PHONY: all clean
```

**如何使用 Makefile**:

1. 将上述内容保存为名为 `Makefile` 的文件（注意大小写）在 `kp_abe.cpp` 所在的目录。

2. 在终端中，导航到该目录。

3. 运行 `make` 命令来编译代码：

   ```bash
   make
   ```

   如果编译成功，会生成一个名为 `kp_abe` 的可执行文件。

4. 运行 `make clean` 命令来删除生成的可执行文件：

   ```bash
   make clean
   ```

**三、 代码运行的预期结果**

当您成功编译 (`make`) 并运行 (`./kp_abe`) 代码后，您应该在终端看到类似以下的输出：

```
Generating Type A parameters (rbits=160, qbits=512)...
Using symmetric pairing (G1=G2).
Global generator g initialized.
Running Setup...
Setup Complete.
Running Key Generation...
Key Generation Complete.
Running Encryption for attributes: { ADMIN CS STUDENT }
Encryption Complete.
Running Decryption...
Decryption Successful.
SUCCESS: Decrypted message matches original message!

--- Testing Decryption Failure Case ---
Running Encryption for attributes: { EE STUDENT }
Encryption Complete.
Running Decryption...
Decryption Failed: Ciphertext attributes do not satisfy the key's access policy.
SUCCESS (expected failure): Decryption correctly failed for non-matching attributes.
Pairing cleared. Exiting.
```

**输出解释**:

1.  `Generating Type A parameters...`: PBC 库正在初始化，使用指定的参数生成配对。
2.  `Using symmetric pairing...`: 确认了使用的配对类型（Type A 通常是对称的）。
3.  `Global generator g initialized.`: G1 群的生成元 g 已设置。
4.  `Running Setup... Setup Complete.`: Setup 阶段执行并完成，生成了公钥 PK 和主密钥 MK。
5.  `Running Key Generation... Key Generation Complete.`: KeyGen 阶段执行并完成，为示例访问策略生成了私钥 SK。
6.  `Running Encryption for attributes: { ADMIN CS STUDENT } ... Encryption Complete.`: 对一个随机消息 M 使用属性集 {"STUDENT", "CS", "ADMIN"} 进行加密。这个属性集满足密钥策略 `(("STUDENT" AND "CS") OR ("STAFF" AND "EE"))` 中的左侧分支。
7.  `Running Decryption... Decryption Successful.`: 使用生成的私钥 SK 解密密文 CT。
8.  `SUCCESS: Decrypted message matches original message!`: 验证解密得到的消息与原始消息 M 相同，证明首次加密解密成功。
9.  `--- Testing Decryption Failure Case ---`: 开始测试一个预期会失败的场景。
10.  `Running Encryption for attributes: { EE STUDENT } ... Encryption Complete.`: 使用属性集 {"STUDENT", "EE"} 加密原始消息。这个属性集 *不满足* 密钥策略（它既不满足 "STUDENT" AND "CS"，也不满足 "STAFF" AND "EE"）。
11.  `Running Decryption...`: 尝试使用私钥 SK 解密这个新的密文 CT_fail。
12.  `Decryption Failed: Ciphertext attributes do not satisfy the key's access policy.`: 解密函数内部首先检查了属性集是否满足访问树策略，发现不满足，因此报告失败（这是预期的）。
13.  `SUCCESS (expected failure): Decryption correctly failed...`: `main` 函数确认解密函数返回了 `false`（失败），这符合预期，因为属性集不匹配。
14.  `Pairing cleared. Exiting.`: 程序结束前清理 PBC 库资源。

请注意，由于随机数的选择（在 Setup、KeyGen、Encrypt 中），每次运行的具体元素值会不同，但程序逻辑和最终的成功/失败结果应该是相同的。