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
element_t g; // Generator g for G1

// --- RAII Wrapper for element_t ---
class ManagedElement
{
public:
    element_t e;
    bool initialized = false;

    ManagedElement() {} // Default constructor

    // Constructor to initialize based on group
    ManagedElement(element_t group_element, pairing_t p)
    {
        element_init_same_as(e, group_element);
        initialized = true;
    }

    // Constructor to initialize in specific group
    void init_G1(pairing_t p)
    {
        element_init_G1(e, p);
        initialized = true;
    }
    void init_G2(pairing_t p)
    {
        element_init_G2(e, p);
        initialized = true;
    }
    void init_GT(pairing_t p)
    {
        element_init_GT(e, p);
        initialized = true;
    }
    void init_Zr(pairing_t p)
    {
        element_init_Zr(e, p);
        initialized = true;
    }

    // Copy constructor
    ManagedElement(const ManagedElement &other)
    {
        if (other.initialized)
        {
            element_init_same_as(e, other.e);
            element_set(e, other.e);
            initialized = true;
        }
    }

    // Move constructor
    ManagedElement(ManagedElement &&other) noexcept : initialized(other.initialized)
    {
        if (initialized)
        {
            element_init_same_as(e, other.e); // Need to init before move for PBC
            element_set(e, other.e);          // Effectively "moves" value
            element_clear(other.e);           // Clear the source
            other.initialized = false;        // Mark source as uninitialized
        }
    }

    // Copy assignment
    ManagedElement &operator=(const ManagedElement &other)
    {
        if (this != &other)
        {
            if (!initialized && other.initialized)
            {
                element_init_same_as(e, other.e);
                initialized = true;
            }
            else if (initialized && !other.initialized)
            {
                element_clear(e);
                initialized = false;
                return *this; // Assigning an uninitialized element clears the destination
            }
            else if (!initialized && !other.initialized)
            {
                return *this; // Assigning uninitialized to uninitialized does nothing
            }
            // Both initialized, ensure compatible type before setting
            // Note: PBC doesn't have a direct type check, relies on element_init_same_as logic
            element_set(e, other.e);
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
                element_init_same_as(e, other.e); // Need to init before move for PBC
                element_set(e, other.e);          // Effectively "moves" value
                element_clear(other.e);           // Clear the source
                other.initialized = false;        // Mark source as uninitialized
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

    // Access the raw element_t
    element_t &get() { return e; }
    const element_t &get() const { return e; }
};

// --- Data Structures ---

struct TreeNode
{
    bool is_leaf = false;
    int kx = 0;              // Threshold (k)
    std::string attribute;   // Attribute (for leaves)
    int index_in_parent = 0; // 1-based index among siblings

    std::vector<std::unique_ptr<TreeNode>> children;

    // Transient data for KeyGen/Decrypt (cleared after use if needed)
    ManagedElement polynomial_value_at_0; // q_x(0) in Zr (set during KeyGen)
    ManagedElement secret_component;      // D_x in G1 (for leaves, set during KeyGen)

    // Constructor for internal node
    TreeNode(int threshold, int index) : is_leaf(false), kx(threshold), index_in_parent(index) {}

    // Constructor for leaf node
    TreeNode(const std::string &attr, int index) : is_leaf(true), kx(1), attribute(attr), index_in_parent(index) {}

    // Recursive deep copy constructor helper
    TreeNode(const TreeNode &other) : is_leaf(other.is_leaf),
                                      kx(other.kx),
                                      attribute(other.attribute),
                                      index_in_parent(other.index_in_parent),
                                      polynomial_value_at_0(other.polynomial_value_at_0), // Copy ManagedElement
                                      secret_component(other.secret_component)            // Copy ManagedElement
    {
        children.reserve(other.children.size());
        for (const auto &child_ptr : other.children)
        {
            children.push_back(std::make_unique<TreeNode>(*child_ptr)); // Recursive copy
        }
    }

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
        Y.init_GT(pairing);
    }
};

struct MasterKey
{
    std::map<std::string, ManagedElement> t; // Attribute -> t_i (Zr)
    ManagedElement y;                        // y (Zr)

    MasterKey()
    {
        y.init_Zr(pairing);
    }
};

// Secret Key holds the structure and the computed components
struct SecretKey
{
    std::unique_ptr<TreeNode> root; // Root of the access tree with computed values

    // Constructor takes ownership of the tree root
    SecretKey(std::unique_ptr<TreeNode> tree_root) : root(std::move(tree_root)) {}

    // Copy constructor for deep copying the tree
    SecretKey(const SecretKey &other)
    {
        if (other.root)
        {
            root = std::make_unique<TreeNode>(*other.root); // Use TreeNode's copy constructor
        }
    }
    // Default move constructor/assignment should be okay with unique_ptr
    SecretKey(SecretKey &&) = default;
    SecretKey &operator=(SecretKey &&) = default;
};

struct Ciphertext
{
    std::set<std::string> gamma;             // Set of attributes γ used for encryption
    ManagedElement E_prime;                  // E' = M * Y^s (GT)
    std::map<std::string, ManagedElement> E; // Attribute -> E_i = T_i^s (G1)

    Ciphertext()
    {
        E_prime.init_GT(pairing);
    }
};

// --- Helper Functions ---

// Initialize PBC Pairing (Type A)
void init_pairing(int rbits = 160, int qbits = 512)
{
    pbc_param_t param;
    std::cout << "Generating Type A parameters (rbits=" << rbits << ", qbits=" << qbits << ")..." << std::endl;
    pbc_param_init_a_gen(param, rbits, qbits);
    pairing_init_pbc_param(pairing, param);
    pbc_param_clear(param);

    if (!pairing_is_symmetric(pairing))
    {
        std::cout << "Using asymmetric pairing." << std::endl;
        // You might need different G1/G2 initialization if truly asymmetric is needed
        // but Type A generated this way is often used symmetrically (G1=G2).
    }
    else
    {
        std::cout << "Using symmetric pairing (G1=G2)." << std::endl;
    }

    // Initialize global generator g
    element_init_G1(g, pairing);
    element_random(g); // Get a random generator
    std::cout << "Global generator g initialized." << std::endl;

    // Make elements print compactly
    element_set_str(g, element_get_str(g, 10), 10); // Example: re-parse to canonicalize if needed
}

// Evaluate polynomial q(x) at point x=eval_point, given coefficients (q[0] = q(0), q[1]..)
void evaluate_polynomial(ManagedElement &result, const std::vector<ManagedElement> &q_coeffs, int eval_point)
{
    if (q_coeffs.empty())
    {
        throw std::runtime_error("Polynomial has no coefficients.");
    }
    result.init_Zr(pairing);
    element_set0(result.get()); // Start with 0

    ManagedElement x_pow_i;
    x_pow_i.init_Zr(pairing);
    ManagedElement term;
    term.init_Zr(pairing);
    ManagedElement eval_p_elem;
    eval_p_elem.init_Zr(pairing);
    element_set_si(eval_p_elem.get(), eval_point); // eval_point as Zr element

    element_set1(x_pow_i.get()); // x^0 = 1

    for (size_t i = 0; i < q_coeffs.size(); ++i)
    {
        // Term = q_coeffs[i] * (eval_point ^ i)
        element_mul(term.get(), q_coeffs[i].get(), x_pow_i.get());
        element_add(result.get(), result.get(), term.get());

        // Update x_pow_i for next iteration: x_pow_i = x_pow_i * eval_point
        if (i + 1 < q_coeffs.size())
        { // No need to compute for the last coefficient
            element_mul(x_pow_i.get(), x_pow_i.get(), eval_p_elem.get());
        }
    }
}

// Calculate Lagrange coefficient Δ_{index_i, S}(0) in Zp
void LagrangeCoeff(ManagedElement &result, int index_i, const std::vector<int> &S_indices)
{
    result.init_Zr(pairing);
    element_set1(result.get()); // Initialize result to 1

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
            continue; // Skip i=j

        element_set_si(elem_j.get(), index_j);

        // Numerator: 0 - j = -j
        element_neg(num.get(), elem_j.get());

        // Denominator: i - j
        element_sub(den.get(), elem_i.get(), elem_j.get());
        if (element_is0(den.get()))
        {
            throw std::runtime_error("Lagrange denominator is zero (duplicate index?)");
        }

        // Inverse of denominator
        element_invert(inv_den.get(), den.get());

        // Term = num / den = num * inv_den
        element_mul(term.get(), num.get(), inv_den.get());

        // result = result * term
        element_mul(result.get(), result.get(), term.get());
    }
}

// Recursive function for KeyGen polynomial assignment and component calculation
void generate_polynomials_and_components(
    TreeNode *node,
    ManagedElement &parent_poly_val_at_node_index, // q_{parent}(index(node))
    const MasterKey &mk,
    const PublicKey &pk // Need pk.g
)
{
    node->polynomial_value_at_0 = parent_poly_val_at_node_index; // q_x(0) = q_{parent}(index(x))
    node->polynomial_value_at_0.init_Zr(pairing);                // Ensure initialized if not already
    element_set(node->polynomial_value_at_0.get(), parent_poly_val_at_node_index.get());

    if (node->is_leaf)
    {
        // --- Leaf Node: Compute Secret Component D_x ---
        const std::string &attr = node->attribute;
        auto it_t = mk.t.find(attr);
        if (it_t == mk.t.end())
        {
            throw std::runtime_error("Attribute '" + attr + "' not found in Master Key during KeyGen for leaf.");
        }
        const ManagedElement &ti = it_t->second;

        ManagedElement inv_ti;
        inv_ti.init_Zr(pairing);
        ManagedElement exponent;
        exponent.init_Zr(pairing);

        // Calculate 1 / t_i
        element_invert(inv_ti.get(), ti.get());

        // Calculate exponent = q_x(0) / t_i = q_x(0) * inv_ti
        element_mul(exponent.get(), node->polynomial_value_at_0.get(), inv_ti.get());

        // Calculate D_x = g ^ exponent
        node->secret_component.init_G1(pairing);
        element_pow_zn(node->secret_component.get(), g, exponent.get()); // Use global g
    }
    else
    {
        // --- Internal Node: Define polynomial and recurse ---
        int degree = node->kx - 1;
        if (degree < 0)
        {
            throw std::runtime_error("Node threshold kx must be >= 1");
        }

        // Define polynomial q_x. q_x(0) is already set. Need degree random coefficients.
        std::vector<ManagedElement> q_coeffs(degree + 1);
        q_coeffs[0] = node->polynomial_value_at_0; // q_x(0) is the constant term

        for (int i = 1; i <= degree; ++i)
        {
            q_coeffs[i].init_Zr(pairing);
            element_random(q_coeffs[i].get());
        }

        // Recurse for children
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

            generate_polynomials_and_components(child, qx_at_child_index, mk, pk);
        }
    }
}

// Recursive function for Decryption logic
bool decrypt_node(
    ManagedElement &result, // Output: GT element if successful
    const TreeNode *node,
    const Ciphertext &ct
    // Secret key components are now within the node structure (node->secret_component)
)
{
    if (node->is_leaf)
    {
        // --- Leaf Node ---
        const std::string &attr = node->attribute;

        // Check if leaf attribute is in the ciphertext attributes γ
        auto it_ct_E = ct.E.find(attr);
        if (it_ct_E == ct.E.end())
        {
            // Attribute not present in ciphertext, this path fails
            return false;
        }
        const ManagedElement &Ei = it_ct_E->second; // E_i = T_i^s = (g^t_i)^s

        // D_x = g^(q_x(0)/t_i)
        const ManagedElement &Dx = node->secret_component;
        if (!Dx.initialized)
        {
            std::cerr << "Warning: Secret component for leaf '" << attr << "' not initialized." << std::endl;
            return false; // Cannot proceed without Dx
        }

        // Compute e(D_x, E_i) = e(g^(q_x(0)/t_i), (g^t_i)^s) = e(g, g)^(q_x(0) * s)
        result.init_GT(pairing);
        pairing_apply(result.get(), Dx.get(), Ei.get(), pairing);
        return true;
    }
    else
    {
        // --- Internal Node ---
        std::vector<std::pair<int, ManagedElement>> valid_child_results; // Stores (index, F_z)
        valid_child_results.reserve(node->children.size());

        for (const auto &child_ptr : node->children)
        {
            ManagedElement child_result; // Temporary result for the child
            if (decrypt_node(child_result, child_ptr.get(), ct))
            {
                valid_child_results.push_back({child_ptr->index_in_parent, std::move(child_result)});
            }
        }

        // Check if enough children satisfied the condition
        if (valid_child_results.size() < node->kx)
        {
            return false; // Threshold not met
        }

        // Select kx children (e.g., the first kx found) for interpolation
        std::vector<int> S_indices;
        S_indices.reserve(node->kx);
        std::vector<ManagedElement> Fz_values;
        Fz_values.reserve(node->kx); // Store F_z for selected indices

        for (int i = 0; i < node->kx; ++i)
        {
            S_indices.push_back(valid_child_results[i].first);
            Fz_values.push_back(std::move(valid_child_results[i].second)); // Move the result
        }

        // Interpolate to find F_x = e(g,g)^(q_x(0)*s)
        result.init_GT(pairing);
        element_set1(result.get()); // Initialize result to 1 in GT

        ManagedElement delta_i; // Lagrange coefficient (Zr)
        ManagedElement term;    // F_z ^ delta_i (GT)

        for (int i = 0; i < node->kx; ++i)
        {
            int current_index = S_indices[i];
            const ManagedElement &current_Fz = Fz_values[i];

            // Calculate Lagrange coefficient Δ_{current_index, S}(0)
            LagrangeCoeff(delta_i, current_index, S_indices);

            // Compute term = F_z ^ delta_i
            term.init_GT(pairing);
            element_pow_zn(term.get(), current_Fz.get(), delta_i.get());

            // Accumulate result = result * term
            element_mul(result.get(), result.get(), term.get());
        }
        return true;
    }
}

// --- Main KP-ABE Algorithms ---

void Setup(PublicKey &pk, MasterKey &mk, const std::set<std::string> &attributes)
{
    std::cout << "Running Setup..." << std::endl;
    // pk.g is global
    mk.y.init_Zr(pairing);
    element_random(mk.y.get());

    ManagedElement temp_gt;
    temp_gt.init_GT(pairing);
    ManagedElement g_pow_y;
    g_pow_y.init_GT(pairing); // Should be e(g,g)^y

    for (const std::string &attr : attributes)
    {
        ManagedElement ti;
        ti.init_Zr(pairing);
        ManagedElement Ti;
        Ti.init_G1(pairing);

        element_random(ti.get());
        element_pow_zn(Ti.get(), g, ti.get()); // Ti = g^ti

        mk.t[attr] = std::move(ti); // Store t_i in MK
        pk.T[attr] = std::move(Ti); // Store T_i in PK
    }

    // Compute Y = e(g,g)^y
    pairing_apply(temp_gt.get(), g, g, pairing);           // temp_gt = e(g,g)
    element_pow_zn(pk.Y.get(), temp_gt.get(), mk.y.get()); // Y = temp_gt^y

    std::cout << "Setup Complete." << std::endl;
}

SecretKey KeyGeneration(const MasterKey &mk, const PublicKey &pk, std::unique_ptr<TreeNode> access_tree_root)
{
    std::cout << "Running Key Generation..." << std::endl;
    if (!access_tree_root)
    {
        throw std::runtime_error("Access tree root cannot be null for Key Generation.");
    }
    if (!mk.y.initialized)
    {
        throw std::runtime_error("Master key 'y' is not initialized.");
    }

    // Start the recursive polynomial assignment from the root
    // q_root(0) is set to y
    generate_polynomials_and_components(access_tree_root.get(), mk.y, mk, pk);

    std::cout << "Key Generation Complete." << std::endl;
    // The tree now contains the secret components D_x in its leaves
    return SecretKey(std::move(access_tree_root));
}

Ciphertext Encrypt(const ManagedElement &M, const std::set<std::string> &gamma, const PublicKey &pk)
{
    std::cout << "Running Encryption for attributes: { ";
    for (const auto &attr : gamma)
        std::cout << attr << " ";
    std::cout << "}" << std::endl;

    if (!M.initialized)
    {
        throw std::runtime_error("Message M is not initialized for encryption.");
    }
    // Basic check: M should be in GT based on our assumption
    // if (!element_ G T() M.get() ... ) { /* PBC has no easy type check */ }

    Ciphertext ct;
    ct.gamma = gamma;

    // Choose random s in Zp
    ManagedElement s;
    s.init_Zr(pairing);
    element_random(s.get());

    // Compute E' = M * Y^s
    ManagedElement Ys;
    Ys.init_GT(pairing);
    element_pow_zn(Ys.get(), pk.Y.get(), s.get()); // Ys = Y^s
    ct.E_prime.init_GT(pairing);
    element_mul(ct.E_prime.get(), M.get(), Ys.get()); // E' = M * Ys

    // Compute E_i = T_i^s for i in gamma
    for (const std::string &attr : gamma)
    {
        auto it_pk_T = pk.T.find(attr);
        if (it_pk_T == pk.T.end())
        {
            throw std::runtime_error("Attribute '" + attr + "' not found in Public Key during Encryption.");
        }
        const ManagedElement &Ti = it_pk_T->second;
        ManagedElement Ei;
        Ei.init_G1(pairing);
        element_pow_zn(Ei.get(), Ti.get(), s.get()); // Ei = Ti^s
        ct.E[attr] = std::move(Ei);
    }

    std::cout << "Encryption Complete." << std::endl;
    return ct;
}

bool Decrypt(ManagedElement &M, const Ciphertext &ct, const SecretKey &sk)
{
    std::cout << "Running Decryption..." << std::endl;
    if (!sk.root)
    {
        throw std::runtime_error("Secret key does not contain a valid access tree.");
    }

    // Check if ciphertext attributes satisfy the key's access policy first (optional but good practice)
    if (!sk.root->check_satisfy(ct.gamma))
    {
        std::cerr << "Decryption Failed: Ciphertext attributes do not satisfy the key's access policy." << std::endl;
        return false;
    }

    ManagedElement A; // To store the result e(g,g)^(y*s) from decrypt_node
    if (decrypt_node(A, sk.root.get(), ct))
    {
        // Decryption successful at root, A = e(g,g)^(ys) = Y^s
        ManagedElement inv_A;
        inv_A.init_GT(pairing);
        element_invert(inv_A.get(), A.get()); // Compute A^(-1)

        // Recover M = E' * A^(-1)
        M.init_GT(pairing);
        element_mul(M.get(), ct.E_prime.get(), inv_A.get());
        std::cout << "Decryption Successful." << std::endl;
        return true;
    }
    else
    {
        std::cerr << "Decryption Failed: DecryptNode recursive call failed." << std::endl;
        M.init_GT(pairing);    // Ensure M is initialized even on failure
        element_set1(M.get()); // Set to identity or some default
        return false;
    }
}

// --- Main Function ---
int main()
{
    try
    {
        init_pairing(160, 512); // Use recommended Type A params

        // 1. Define Attribute Universe
        std::set<std::string> universe = {"STUDENT", "STAFF", "CS", "EE", "ADMIN"};

        // 2. Setup
        PublicKey pk;
        MasterKey mk;
        Setup(pk, mk, universe);

        // 3. Define Access Structure (Key Policy)
        // Example: (("STUDENT" AND "CS") OR ("STAFF" AND "EE"))
        auto root = std::make_unique<TreeNode>(1, 0); // OR gate (k=1), index 0 for root
        root->polynomial_value_at_0.init_Zr(pairing); // Initialize needed fields
        root->secret_component.init_G1(pairing);

        // Left branch: "STUDENT" AND "CS" (k=2)
        auto and1 = std::make_unique<TreeNode>(2, 1); // AND gate (k=2), index 1
        and1->polynomial_value_at_0.init_Zr(pairing);
        and1->secret_component.init_G1(pairing);
        auto leaf_student = std::make_unique<TreeNode>("STUDENT", 1); // index 1 under AND
        leaf_student->polynomial_value_at_0.init_Zr(pairing);
        leaf_student->secret_component.init_G1(pairing);
        auto leaf_cs = std::make_unique<TreeNode>("CS", 2); // index 2 under AND
        leaf_cs->polynomial_value_at_0.init_Zr(pairing);
        leaf_cs->secret_component.init_G1(pairing);

        and1->addChild(std::move(leaf_student));
        and1->addChild(std::move(leaf_cs));

        // Right branch: "STAFF" AND "EE" (k=2)
        auto and2 = std::make_unique<TreeNode>(2, 2); // AND gate (k=2), index 2
        and2->polynomial_value_at_0.init_Zr(pairing);
        and2->secret_component.init_G1(pairing);
        auto leaf_staff = std::make_unique<TreeNode>("STAFF", 1); // index 1 under AND
        leaf_staff->polynomial_value_at_0.init_Zr(pairing);
        leaf_staff->secret_component.init_G1(pairing);
        auto leaf_ee = std::make_unique<TreeNode>("EE", 2); // index 2 under AND
        leaf_ee->polynomial_value_at_0.init_Zr(pairing);
        leaf_ee->secret_component.init_G1(pairing);

        and2->addChild(std::move(leaf_staff));
        and2->addChild(std::move(leaf_ee));

        root->addChild(std::move(and1));
        root->addChild(std::move(and2));

        // 4. Key Generation
        SecretKey sk = KeyGeneration(mk, pk, std::move(root));

        // 5. Define Message
        ManagedElement M_orig;
        M_orig.init_GT(pairing);
        element_random(M_orig.get());
        std::cout << "Original Message M set." << std::endl;
        // element_printf("M_orig = %B\n", M_orig.get());

        // 6. Define Ciphertext Attributes (Access Policy)
        std::set<std::string> gamma = {"STUDENT", "CS", "ADMIN"}; // Satisfies left branch of key policy

        // 7. Encrypt
        Ciphertext ct = Encrypt(M_orig, gamma, pk);

        // 8. Decrypt
        ManagedElement M_dec;
        if (Decrypt(M_dec, ct, sk))
        {
            // element_printf("Decrypted Message M_dec = %B\n", M_dec.get());
            // 9. Verify
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
        std::set<std::string> gamma_fail = {"STUDENT", "EE"}; // Does NOT satisfy the key policy
        Ciphertext ct_fail = Encrypt(M_orig, gamma_fail, pk);
        ManagedElement M_dec_fail;
        if (!Decrypt(M_dec_fail, ct_fail, sk))
        {
            std::cout << "SUCCESS (expected failure): Decryption correctly failed for non-matching attributes." << std::endl;
        }
        else
        {
            std::cerr << "FAILURE (unexpected success): Decryption should have failed but reported success." << std::endl;
            if (!element_cmp(M_orig.get(), M_dec_fail.get()))
            {
                std::cerr << "      -> And the message seems to match? Problematic!" << std::endl;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        // Cleanup pairing even if error occurs
        if (pairing->pbc_param)
            pairing_clear(pairing);
        if (g->field)
            element_clear(g); // Clear global g if initialized
        return 1;
    }

    // Final Cleanup
    pairing_clear(pairing);
    if (g->field)
        element_clear(g); // Clear global g
    std::cout << "Pairing cleared. Exiting." << std::endl;
    return 0;
}