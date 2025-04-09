#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <stdexcept>
#include <memory>         // For unique_ptr
#include <numeric>        // For std::accumulate, iota
#include <openssl/rand.h> // For secure random bytes if needed by PBC

// PBC Header - Must be included after standard headers sometimes
#include <pbc.h>

// --- Global Pairing Variable (for simplicity in this example) ---
pairing_t pairing;
bool pairing_initialized = false; // Flag to track initialization
element_t g;                      // Generator g for G1

// --- RAII Wrapper for element_t ---
class ManagedElement
{
public:
    element_t e;
    bool initialized = false;

    ManagedElement() = default; // Default constructor

    // Constructor to initialize based on group element type (pairing unused)
    ManagedElement(element_t group_element, pairing_t /* p */)
    { // p marked unused or removed
        if (!pairing_initialized)
            throw std::runtime_error("Pairing not initialized for ManagedElement creation");
        // element_init_same_as takes element_t (element_s*)
        element_init_same_as(e, group_element);
        initialized = true;
    }

    // Constructor to initialize in specific group
    void init_G1(pairing_t p)
    {
        if (!initialized)
        {
            element_init_G1(e, p);
            initialized = true;
        }
    }
    void init_G2(pairing_t p)
    {
        if (!initialized)
        {
            element_init_G2(e, p);
            initialized = true;
        }
    }
    void init_GT(pairing_t p)
    {
        if (!initialized)
        {
            element_init_GT(e, p);
            initialized = true;
        }
    }
    void init_Zr(pairing_t p)
    {
        if (!initialized)
        {
            element_init_Zr(e, p);
            initialized = true;
        }
    }

    // Copy constructor
    ManagedElement(const ManagedElement &other)
    {
        if (other.initialized)
        {
            // Correctly cast the pointer obtained from decaying the array reference
            element_init_same_as(e, const_cast<element_s *>(other.get()));
            element_set(e, const_cast<element_s *>(other.get()));
            initialized = true;
        }
    }

    // Move constructor
    ManagedElement(ManagedElement &&other) noexcept : initialized(other.initialized)
    {
        if (initialized)
        {
            // Move involves copying the internal state pointer and clearing the old one
            e[0] = other.e[0];         // Directly move the struct content is okay for pbc element_t
            other.initialized = false; // Mark source as uninitialized (it holds nothing valid now)
        }
    }

    // Copy assignment (corrected logic)
    ManagedElement &operator=(const ManagedElement &other)
    {
        if (this != &other)
        {
            if (!other.initialized)
            { // If other is uninitialized, clear this one
                if (initialized)
                    element_clear(e);
                initialized = false;
            }
            else
            { // Other is initialized
                if (!initialized)
                { // If this wasn't initialized, init it first
                    // Correctly cast the pointer obtained from decaying the array reference
                    element_init_same_as(e, const_cast<element_s *>(other.get()));
                    initialized = true;
                }
                // Set the value (works whether 'this' was initialized or not)
                // Correctly cast the pointer obtained from decaying the array reference
                element_set(e, const_cast<element_s *>(other.get()));
            }
        }
        return *this;
    }

    // Move assignment
    ManagedElement &operator=(ManagedElement &&other) noexcept
    {
        if (this != &other)
        {
            if (initialized)
            {
                element_clear(e); // Clear existing resource
            }
            initialized = other.initialized;
            if (initialized)
            {
                e[0] = other.e[0];         // Directly move the struct content
                other.initialized = false; // Mark source as uninitialized
            }
        }
        return *this;
    }

    // Destructor
    ~ManagedElement()
    {
        if (initialized)
        {
            element_clear(e);
        }
    }

    // Access the raw element_t (const and non-const versions)
    element_t &get() { return e; }
    const element_t &get() const { return e; } // Const version returning const reference
};

// --- Data Structures ---

struct TreeNode
{
    bool is_leaf = false;
    int kx = 0;              // Threshold (k)
    std::string attribute;   // Attribute (for leaves)
    int index_in_parent = 0; // 1-based index among siblings

    std::vector<std::unique_ptr<TreeNode>> children;

    // Transient data for KeyGen/Decrypt
    ManagedElement polynomial_value_at_0; // q_x(0) in Zr
    ManagedElement secret_component;      // D_x in G1 (for leaves)

    // Constructor for internal node
    TreeNode(int threshold, int index) : is_leaf(false), kx(threshold), index_in_parent(index) {}

    // Constructor for leaf node
    TreeNode(const std::string &attr, int index) : is_leaf(true), kx(1), attribute(attr), index_in_parent(index) {}

    // Recursive deep copy constructor helper
    TreeNode(const TreeNode &other) : is_leaf(other.is_leaf),
                                      kx(other.kx),
                                      attribute(other.attribute),
                                      index_in_parent(other.index_in_parent),
                                      polynomial_value_at_0(other.polynomial_value_at_0),
                                      secret_component(other.secret_component)
    {
        children.reserve(other.children.size());
        for (const auto &child_ptr : other.children)
        {
            children.push_back(std::make_unique<TreeNode>(*child_ptr));
        }
    }
    // Default move constructor is okay for unique_ptr members
    TreeNode(TreeNode &&) = default;
    TreeNode &operator=(const TreeNode &) = delete; // Avoid shallow copies
    TreeNode &operator=(TreeNode &&) = default;     // Allow move assignment

    // Add child (takes ownership)
    void addChild(std::unique_ptr<TreeNode> child)
    {
        children.push_back(std::move(child));
    }

    int numChildren() const { return children.size(); }

    // Helper to check if attribute set satisfies the subtree rooted at this node
    bool check_satisfy(const std::set<std::string> &gamma) const
    {
        if (is_leaf)
        {
            return gamma.count(attribute) > 0;
        }
        else
        {
            int satisfied_children = 0;
            for (const auto &child : children)
            {
                if (child->check_satisfy(gamma))
                {
                    satisfied_children++;
                }
            }
            return satisfied_children >= kx;
        }
    }
};

struct PublicKey
{
    // element_t g is global for simplicity here
    std::map<std::string, ManagedElement> T; // Attribute -> T_i (G1)
    ManagedElement Y;                        // Y = e(g,g)^y (GT)

    PublicKey()
    {
        if (!pairing_initialized)
            throw std::runtime_error("Pairing not initialized for PublicKey creation");
        Y.init_GT(pairing);
    }
};

struct MasterKey
{
    std::map<std::string, ManagedElement> t; // Attribute -> t_i (Zr)
    ManagedElement y;                        // y (Zr)

    MasterKey()
    {
        if (!pairing_initialized)
            throw std::runtime_error("Pairing not initialized for MasterKey creation");
        y.init_Zr(pairing);
    }
};

struct SecretKey
{
    std::unique_ptr<TreeNode> root; // Root of the access tree with computed values

    SecretKey(std::unique_ptr<TreeNode> tree_root) : root(std::move(tree_root)) {}

    SecretKey(const SecretKey &other)
    {
        if (other.root)
        {
            root = std::make_unique<TreeNode>(*other.root);
        }
    }
    SecretKey(SecretKey &&) = default;
    SecretKey &operator=(SecretKey &&) = default;
};

struct Ciphertext
{
    std::set<std::string> gamma;
    ManagedElement E_prime;                  // E' = M * Y^s (GT)
    std::map<std::string, ManagedElement> E; // Attribute -> E_i = T_i^s (G1)

    Ciphertext()
    {
        if (!pairing_initialized)
            throw std::runtime_error("Pairing not initialized for Ciphertext creation");
        E_prime.init_GT(pairing);
    }
};

// --- Helper Functions ---

void init_pairing(int rbits = 160, int qbits = 512)
{
    if (pairing_initialized)
        return;

    pbc_param_t param;
    std::cout << "Generating Type A parameters (rbits=" << rbits << ", qbits=" << qbits << ")..." << std::endl;
    pbc_param_init_a_gen(param, rbits, qbits);
    pairing_init_pbc_param(pairing, param);
    pbc_param_clear(param);

    if (!pairing_is_symmetric(pairing))
    {
        std::cout << "Using asymmetric pairing." << std::endl;
    }
    else
    {
        std::cout << "Using symmetric pairing (G1=G2)." << std::endl;
    }

    element_init_G1(g, pairing);
    element_random(g);
    std::cout << "Global generator g initialized." << std::endl;
    pairing_initialized = true;
}

void evaluate_polynomial(ManagedElement &result, const std::vector<ManagedElement> &q_coeffs, int eval_point)
{
    if (q_coeffs.empty())
    {
        throw std::runtime_error("Polynomial has no coefficients.");
    }
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for evaluate_polynomial");
    result.init_Zr(pairing);
    element_set0(result.get());

    ManagedElement x_pow_i;
    x_pow_i.init_Zr(pairing);
    ManagedElement term;
    term.init_Zr(pairing);
    ManagedElement eval_p_elem;
    eval_p_elem.init_Zr(pairing);
    element_set_si(eval_p_elem.get(), eval_point);

    element_set1(x_pow_i.get());

    for (size_t i = 0; i < q_coeffs.size(); ++i)
    {
        // Correctly cast the pointer obtained from decay
        element_mul(term.get(), const_cast<element_s *>(q_coeffs[i].get()), x_pow_i.get());
        element_add(result.get(), result.get(), term.get());

        if (i + 1 < q_coeffs.size())
        {
            element_mul(x_pow_i.get(), x_pow_i.get(), eval_p_elem.get());
        }
    }
}

void LagrangeCoeff(ManagedElement &result, int index_i, const std::vector<int> &S_indices)
{
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for LagrangeCoeff");
    result.init_Zr(pairing);
    element_set1(result.get());

    ManagedElement num;
    num.init_Zr(pairing);
    ManagedElement den;
    den.init_Zr(pairing);
    ManagedElement inv_den;
    inv_den.init_Zr(pairing);
    ManagedElement term;
    term.init_Zr(pairing);
    ManagedElement elem_i;
    elem_i.init_Zr(pairing);
    ManagedElement elem_j;
    elem_j.init_Zr(pairing);

    element_set_si(elem_i.get(), index_i);

    for (int index_j : S_indices)
    {
        if (index_i == index_j)
            continue;

        element_set_si(elem_j.get(), index_j);
        element_neg(num.get(), elem_j.get());
        element_sub(den.get(), elem_i.get(), elem_j.get());
        if (element_is0(den.get()))
        {
            throw std::runtime_error("Lagrange denominator is zero (duplicate index?)");
        }
        element_invert(inv_den.get(), den.get());
        element_mul(term.get(), num.get(), inv_den.get());
        element_mul(result.get(), result.get(), term.get());
    }
}

void generate_polynomials_and_components(
    TreeNode *node,
    const ManagedElement &parent_poly_val_at_node_index, // CONST reference
    const MasterKey &mk,
    const PublicKey &pk)
{
    if (!node)
        return;
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for generate_polynomials");

    node->polynomial_value_at_0.init_Zr(pairing);
    // Correctly cast the pointer obtained from decay
    element_set(node->polynomial_value_at_0.get(), const_cast<element_s *>(parent_poly_val_at_node_index.get()));

    if (node->is_leaf)
    {
        const std::string &attr = node->attribute;
        auto it_t = mk.t.find(attr);
        if (it_t == mk.t.end())
        {
            throw std::runtime_error("Attribute '" + attr + "' not found in Master Key during KeyGen for leaf.");
        }
        const ManagedElement &ti = it_t->second; // ti is const

        ManagedElement inv_ti;
        inv_ti.init_Zr(pairing);
        ManagedElement exponent;
        exponent.init_Zr(pairing);

        // Correctly cast the pointer obtained from decay
        element_invert(inv_ti.get(), const_cast<element_s *>(ti.get()));
        element_mul(exponent.get(), node->polynomial_value_at_0.get(), inv_ti.get());

        node->secret_component.init_G1(pairing);
        element_pow_zn(node->secret_component.get(), g, exponent.get());
    }
    else
    {
        int degree = node->kx - 1;
        if (degree < 0)
        {
            throw std::runtime_error("Node threshold kx must be >= 1");
        }

        std::vector<ManagedElement> q_coeffs(degree + 1);
        q_coeffs[0].init_Zr(pairing);
        element_set(q_coeffs[0].get(), node->polynomial_value_at_0.get());

        for (int i = 1; i <= degree; ++i)
        {
            q_coeffs[i].init_Zr(pairing);
            element_random(q_coeffs[i].get());
        }

        for (auto &child_ptr : node->children)
        {
            TreeNode *child = child_ptr.get();
            int child_index = child->index_in_parent;
            if (child_index == 0)
            {
                throw std::runtime_error("Child index cannot be 0 for polynomial evaluation.");
            }

            ManagedElement qx_at_child_index;
            evaluate_polynomial(qx_at_child_index, q_coeffs, child_index);
            // Pass the non-const qx_at_child_index recursively
            generate_polynomials_and_components(child, qx_at_child_index, mk, pk);
        }
    }
}

bool decrypt_node(
    ManagedElement &result,
    const TreeNode *node, // CONST node
    const Ciphertext &ct)
{
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for decrypt_node");
    if (!node)
        return false;

    if (node->is_leaf)
    {
        const std::string &attr = node->attribute;
        auto it_ct_E = ct.E.find(attr);
        if (it_ct_E == ct.E.end())
        {
            return false;
        }
        const ManagedElement &Ei = it_ct_E->second;        // Ei is const
        const ManagedElement &Dx = node->secret_component; // Dx is const

        if (!Dx.initialized)
        {
            std::cerr << "Warning: Secret component for leaf '" << attr << "' not initialized." << std::endl;
            return false;
        }

        result.init_GT(pairing);
        // Correctly cast the pointers obtained from decay
        pairing_apply(result.get(), const_cast<element_s *>(Dx.get()), const_cast<element_s *>(Ei.get()), pairing);
        return true;
    }
    else
    {
        std::vector<std::pair<int, ManagedElement>> valid_child_results;
        valid_child_results.reserve(node->children.size());

        for (const auto &child_ptr : node->children)
        {
            ManagedElement child_result;
            if (decrypt_node(child_result, child_ptr.get(), ct))
            {
                valid_child_results.push_back({child_ptr->index_in_parent, std::move(child_result)});
            }
        }

        if (valid_child_results.size() < static_cast<size_t>(node->kx))
        {
            return false;
        }

        std::vector<int> S_indices;
        S_indices.reserve(node->kx);
        std::vector<ManagedElement> Fz_values;
        Fz_values.reserve(node->kx);

        for (int i = 0; i < node->kx; ++i)
        {
            S_indices.push_back(valid_child_results[i].first);
            Fz_values.push_back(std::move(valid_child_results[i].second));
        }

        result.init_GT(pairing);
        element_set1(result.get());

        ManagedElement delta_i;
        ManagedElement term;

        for (int i = 0; i < node->kx; ++i)
        {
            int current_index = S_indices[i];
            const ManagedElement &current_Fz = Fz_values[i]; // Fz is const

            LagrangeCoeff(delta_i, current_index, S_indices);

            term.init_GT(pairing);
            // Correctly cast the pointer obtained from decay
            element_pow_zn(term.get(), const_cast<element_s *>(current_Fz.get()), delta_i.get());
            element_mul(result.get(), result.get(), term.get());
        }
        return true;
    }
}

// --- Main KP-ABE Algorithms ---

void Setup(PublicKey &pk, MasterKey &mk, const std::set<std::string> &attributes)
{
    std::cout << "Running Setup..." << std::endl;
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for Setup");
    element_random(mk.y.get());

    ManagedElement temp_gt;
    temp_gt.init_GT(pairing);

    for (const std::string &attr : attributes)
    {
        ManagedElement ti;
        ti.init_Zr(pairing);
        ManagedElement Ti;
        Ti.init_G1(pairing);

        element_random(ti.get());
        element_pow_zn(Ti.get(), g, ti.get());

        mk.t[attr] = std::move(ti);
        pk.T[attr] = std::move(Ti);
    }

    pairing_apply(temp_gt.get(), g, g, pairing);
    element_pow_zn(pk.Y.get(), temp_gt.get(), mk.y.get());

    std::cout << "Setup Complete." << std::endl;
}

SecretKey KeyGeneration(const MasterKey &mk, const PublicKey &pk, std::unique_ptr<TreeNode> access_tree_root)
{
    std::cout << "Running Key Generation..." << std::endl;
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for KeyGen");
    if (!access_tree_root)
    {
        throw std::runtime_error("Access tree root cannot be null for Key Generation.");
    }
    if (!mk.y.initialized)
    {
        throw std::runtime_error("Master key 'y' is not initialized.");
    }

    generate_polynomials_and_components(access_tree_root.get(), mk.y, mk, pk);

    std::cout << "Key Generation Complete." << std::endl;
    return SecretKey(std::move(access_tree_root));
}

Ciphertext Encrypt(const ManagedElement &M, // CONST M
                   const std::set<std::string> &gamma,
                   const PublicKey &pk // CONST pk
)
{
    std::cout << "Running Encryption for attributes: { ";
    for (const auto &attr : gamma)
        std::cout << attr << " ";
    std::cout << "}" << std::endl;
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for Encrypt");

    if (!M.initialized)
    {
        throw std::runtime_error("Message M is not initialized for encryption.");
    }

    Ciphertext ct;
    ct.gamma = gamma;

    ManagedElement s;
    s.init_Zr(pairing);
    element_random(s.get());

    ManagedElement Ys;
    Ys.init_GT(pairing);
    // Correctly cast the pointer obtained from decay
    element_pow_zn(Ys.get(), const_cast<element_s *>(pk.Y.get()), s.get());
    // Correctly cast the pointer obtained from decay
    element_mul(ct.E_prime.get(), const_cast<element_s *>(M.get()), Ys.get());

    for (const std::string &attr : gamma)
    {
        auto it_pk_T = pk.T.find(attr);
        if (it_pk_T == pk.T.end())
        {
            throw std::runtime_error("Attribute '" + attr + "' not found in Public Key during Encryption.");
        }
        const ManagedElement &Ti = it_pk_T->second; // Ti is const
        ManagedElement Ei;
        Ei.init_G1(pairing);
        // Correctly cast the pointer obtained from decay
        element_pow_zn(Ei.get(), const_cast<element_s *>(Ti.get()), s.get());
        ct.E[attr] = std::move(Ei);
    }

    std::cout << "Encryption Complete." << std::endl;
    return ct;
}

bool Decrypt(ManagedElement &M,    // Output M
             const Ciphertext &ct, // CONST ct
             const SecretKey &sk   // CONST sk
)
{
    std::cout << "Running Decryption..." << std::endl;
    if (!pairing_initialized)
        throw std::runtime_error("Pairing not initialized for Decrypt");
    if (!sk.root)
    {
        throw std::runtime_error("Secret key does not contain a valid access tree.");
    }

    if (!sk.root->check_satisfy(ct.gamma))
    {
        std::cerr << "Decryption Failed: Ciphertext attributes do not satisfy the key's access policy." << std::endl;
        return false;
    }

    ManagedElement A;
    if (decrypt_node(A, sk.root.get(), ct))
    {
        ManagedElement inv_A;
        inv_A.init_GT(pairing);
        element_invert(inv_A.get(), A.get());

        M.init_GT(pairing);
        // Correctly cast the pointer obtained from decay
        element_mul(M.get(), const_cast<element_s *>(ct.E_prime.get()), inv_A.get());
        std::cout << "Decryption Successful." << std::endl;
        return true;
    }
    else
    {
        std::cerr << "Decryption Failed: DecryptNode recursive call failed." << std::endl;
        M.init_GT(pairing);
        element_set1(M.get());
        return false;
    }
}

// --- Main Function ---
int main()
{
    try
    {
        init_pairing(160, 512);

        // 1. Define Attribute Universe
        std::set<std::string> universe = {"STUDENT", "STAFF", "CS", "EE", "ADMIN"};

        // 2. Setup
        PublicKey pk;
        MasterKey mk;
        Setup(pk, mk, universe);

        // 3. Define Access Structure (Key Policy)
        auto root = std::make_unique<TreeNode>(1, 0);
        auto and1 = std::make_unique<TreeNode>(2, 1);
        and1->addChild(std::make_unique<TreeNode>("STUDENT", 1));
        and1->addChild(std::make_unique<TreeNode>("CS", 2));
        auto and2 = std::make_unique<TreeNode>(2, 2);
        and2->addChild(std::make_unique<TreeNode>("STAFF", 1));
        and2->addChild(std::make_unique<TreeNode>("EE", 2));
        root->addChild(std::move(and1));
        root->addChild(std::move(and2));

        // 4. Key Generation
        SecretKey sk = KeyGeneration(mk, pk, std::move(root));

        // 5. Define Message
        ManagedElement M_orig;
        M_orig.init_GT(pairing);
        element_random(M_orig.get());
        std::cout << "Original Message M set." << std::endl;

        // 6. Define Ciphertext Attributes
        std::set<std::string> gamma = {"STUDENT", "CS", "ADMIN"};

        // 7. Encrypt
        Ciphertext ct = Encrypt(M_orig, gamma, pk);

        // 8. Decrypt
        ManagedElement M_dec;
        if (Decrypt(M_dec, ct, sk))
        {
            if (!element_cmp(M_orig.get(), M_dec.get()))
            {
                std::cout << "SUCCESS: Decrypted message matches original message!" << std::endl;
            }
            else
            {
                std::cerr << "FAILURE: Decrypted message does NOT match original message." << std::endl;
            }
        }
        else
        {
            std::cerr << "FAILURE: Decryption process failed." << std::endl;
        }

        // --- Test case that should fail ---
        std::cout << "\n--- Testing Decryption Failure Case ---" << std::endl;
        std::set<std::string> gamma_fail = {"STUDENT", "EE"};
        Ciphertext ct_fail = Encrypt(M_orig, gamma_fail, pk);
        ManagedElement M_dec_fail;
        if (!Decrypt(M_dec_fail, ct_fail, sk))
        {
            std::cout << "SUCCESS (expected failure): Decryption correctly failed for non-matching attributes." << std::endl;
        }
        else
        {
            std::cerr << "FAILURE (unexpected success): Decryption should have failed but reported success." << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        // Cleanup pairing only if it was initialized
        if (pairing_initialized)
        {
            // Clear element first, then pairing
            if (g->field)
                element_clear(g); // Check if g was initialized (redundant if pairing_init succeeded)
            pairing_clear(pairing);
            pairing_initialized = false; // Mark as cleared
        }
        return 1;
    }

    // Final Cleanup
    if (pairing_initialized)
    {
        // Clear element first, then pairing
        if (g->field)
            element_clear(g); // Check if g was initialized
        pairing_clear(pairing);
        pairing_initialized = false;                           // Mark as cleared
        std::cout << "Pairing cleared. Exiting." << std::endl; // This should now print
    }
    return 0;
}