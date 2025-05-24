#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <stdexcept>
#include <memory> // For unique_ptr
#include <numeric> // For std::accumulate, iota
#include <chrono>  // For timing
#include <iomanip> // For std::setw, std::left

#include <openssl/rand.h> // For secure random bytes if needed by PBC
#include <pbc.h>          // PBC Header

// --- Global Pairing Variable (for simplicity in this example) ---
pairing_t pairing;
bool pairing_initialized = false; // Flag to track initialization
element_t g; // Generator g for G1

// --- RAII Wrapper for element_t ---
// (ManagedElement class definition remains the same as the previous working version)
class ManagedElement {
public:
    element_t e;
    bool initialized = false;

    ManagedElement() = default; // Default constructor

    // Constructor to initialize based on group element type (pairing unused)
    ManagedElement(element_t group_element, pairing_t /* p */) { // p marked unused or removed
        if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for ManagedElement creation");
        // element_init_same_as takes element_t (element_s*)
        element_init_same_as(e, group_element);
        initialized = true;
    }

    // Constructor to initialize in specific group
    void init_G1(pairing_t p) { if(!initialized) { element_init_G1(e, p); initialized = true; } }
    void init_G2(pairing_t p) { if(!initialized) { element_init_G2(e, p); initialized = true; } }
    void init_GT(pairing_t p) { if(!initialized) { element_init_GT(e, p); initialized = true; } }
    void init_Zr(pairing_t p) { if(!initialized) { element_init_Zr(e, p); initialized = true; } }

    // Copy constructor
    ManagedElement(const ManagedElement& other) {
        if (other.initialized) {
            // Correctly cast the pointer obtained from decaying the array reference
            element_init_same_as(e, const_cast<element_s*>(other.get()));
            element_set(e, const_cast<element_s*>(other.get()));
            initialized = true;
        }
    }

    // Move constructor
    ManagedElement(ManagedElement&& other) noexcept : initialized(other.initialized) {
        if (initialized) {
             // Move involves copying the internal state pointer and clearing the old one
             e[0] = other.e[0]; // Directly move the struct content is okay for pbc element_t
             other.initialized = false; // Mark source as uninitialized (it holds nothing valid now)
        }
    }


    // Copy assignment (corrected logic)
     ManagedElement& operator=(const ManagedElement& other) {
        if (this != &other) {
            if (!other.initialized) { // If other is uninitialized, clear this one
                 if(initialized) element_clear(e);
                 initialized = false;
            } else { // Other is initialized
                if (!initialized) { // If this wasn't initialized, init it first
                    // Correctly cast the pointer obtained from decaying the array reference
                    element_init_same_as(e, const_cast<element_s*>(other.get()));
                    initialized = true;
                }
                // Set the value (works whether 'this' was initialized or not)
                // Correctly cast the pointer obtained from decaying the array reference
                element_set(e, const_cast<element_s*>(other.get()));
            }
        }
        return *this;
    }


    // Move assignment
     ManagedElement& operator=(ManagedElement&& other) noexcept {
        if (this != &other) {
            if (initialized) {
                element_clear(e); // Clear existing resource
            }
            initialized = other.initialized;
            if (initialized) {
                e[0] = other.e[0]; // Directly move the struct content
                other.initialized = false; // Mark source as uninitialized
            }
        }
        return *this;
    }


    // Destructor
    ~ManagedElement() {
        if (initialized) {
            element_clear(e);
        }
    }

    // Access the raw element_t (const and non-const versions)
    element_t& get() { return e; }
    const element_t& get() const { return e; } // Const version returning const reference
};

// --- Data Structures ---
struct TreeNode {
    bool is_leaf = false;
    int kx = 0;
    std::string attribute; // For leaves
    int index_in_parent = 0;
    std::string name; // Optional name for internal nodes (e.g., "AND", "OR")

    std::vector<std::unique_ptr<TreeNode>> children;

    ManagedElement polynomial_value_at_0;
    ManagedElement secret_component;

    // Constructor for internal node
    TreeNode(int threshold, int index, std::string node_name = "") :
        is_leaf(false), kx(threshold), index_in_parent(index), name(node_name) {}

    // Constructor for leaf node
    TreeNode(const std::string& attr, int index) :
        is_leaf(true), kx(1), attribute(attr), index_in_parent(index) {}

     // Recursive deep copy constructor helper
    TreeNode(const TreeNode& other) :
        is_leaf(other.is_leaf), kx(other.kx), attribute(other.attribute),
        index_in_parent(other.index_in_parent), name(other.name),
        polynomial_value_at_0(other.polynomial_value_at_0),
        secret_component(other.secret_component)
    {
        children.reserve(other.children.size());
        for (const auto& child_ptr : other.children) {
            children.push_back(std::make_unique<TreeNode>(*child_ptr));
        }
    }
    TreeNode(TreeNode&&) = default;
    TreeNode& operator=(const TreeNode&) = delete;
    TreeNode& operator=(TreeNode&&) = default;

    void addChild(std::unique_ptr<TreeNode> child) {
        children.push_back(std::move(child));
    }

    int numChildren() const { return children.size(); }

    bool check_satisfy(const std::set<std::string>& gamma) const {
         if (is_leaf) {
            return gamma.count(attribute) > 0;
        } else {
            int satisfied_children = 0;
            for (const auto& child : children) {
                if (child->check_satisfy(gamma)) {
                    satisfied_children++;
                }
            }
            return satisfied_children >= kx;
        }
    }
};

// Other data structures (PublicKey, MasterKey, SecretKey, Ciphertext) remain the same
struct PublicKey {
    std::map<std::string, ManagedElement> T;
    ManagedElement Y;

    PublicKey() {
        if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for PublicKey creation");
        Y.init_GT(pairing);
    }
};

struct MasterKey {
    std::map<std::string, ManagedElement> t;
    ManagedElement y;

    MasterKey() {
        if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for MasterKey creation");
        y.init_Zr(pairing);
    }
};

struct SecretKey {
     std::unique_ptr<TreeNode> root;
     SecretKey(std::unique_ptr<TreeNode> tree_root) : root(std::move(tree_root)) {}
     SecretKey(const SecretKey& other) { if (other.root) root = std::make_unique<TreeNode>(*other.root); }
     SecretKey(SecretKey&&) = default;
     SecretKey& operator=(SecretKey&&) = default;
};

struct Ciphertext {
    std::set<std::string> gamma;
    ManagedElement E_prime;
    std::map<std::string, ManagedElement> E;

    Ciphertext() {
         if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for Ciphertext creation");
        E_prime.init_GT(pairing);
    }
};


// --- Helper Functions ---

// Function to print attributes
void print_attributes(const std::set<std::string>& attrs, const std::string& label) {
    std::cout << label << ": { ";
    for (auto it = attrs.begin(); it != attrs.end(); ++it) {
        std::cout << *it << (std::next(it) == attrs.end() ? "" : ", ");
    }
    std::cout << " }" << std::endl;
}

// Function to print element (briefly)
void print_element(const ManagedElement& e, const std::string& label) {
    if (e.initialized) {
        std::cout << label << ": ";
        element_printf("%#.10B", e.get()); // Print type and first ~10 Bytes in hex
        std::cout << "..." << std::endl;
    } else {
        std::cout << label << ": (Not Initialized)" << std::endl;
    }
}

// Function to print tree structure
void print_tree(const TreeNode* node, int indent = 0) {
    if (!node) return;
    std::cout << std::string(indent * 2, ' '); // Indentation
    if (node->is_leaf) {
        std::cout << "[Leaf] Attribute: " << node->attribute
                  << " (Index: " << node->index_in_parent << ")" << std::endl;
    } else {
        std::cout << "[Node] ";
        if (!node->name.empty()) {
             std::cout << node->name << " ";
        }
         std::cout << "(k=" << node->kx << " of " << node->numChildren() << ")"
                   << " (Index: " << node->index_in_parent << ")" << std::endl;
        for (const auto& child : node->children) {
            print_tree(child.get(), indent + 1);
        }
    }
}

// Forward declarations of core functions if needed, or ensure definition order
void Setup(PublicKey& pk, MasterKey& mk, const std::set<std::string>& attributes);
SecretKey KeyGeneration(const MasterKey& mk, const PublicKey& pk, std::unique_ptr<TreeNode> access_tree_root);
Ciphertext Encrypt(const ManagedElement& M, const std::set<std::string>& gamma, const PublicKey& pk);
bool Decrypt(ManagedElement& M, const Ciphertext& ct, const SecretKey& sk);

// init_pairing, evaluate_polynomial, LagrangeCoeff, generate_polynomials_and_components, decrypt_node
// remain the same as the previous working version (with const_cast<element_s*>)

// Initialize PBC Pairing (Type A)
void init_pairing(int rbits = 160, int qbits = 512) {
    if (pairing_initialized) return;

    pbc_param_t param;
    std::cout << "Generating Type A parameters (rbits=" << rbits << ", qbits=" << qbits << ")..." << std::endl;
    pbc_param_init_a_gen(param, rbits, qbits);
    pairing_init_pbc_param(pairing, param);
    pbc_param_clear(param);

    if (!pairing_is_symmetric(pairing)) {
         std::cout << "Using asymmetric pairing." << std::endl;
    } else {
         std::cout << "Using symmetric pairing (G1=G2)." << std::endl;
    }

    element_init_G1(g, pairing);
    element_random(g);
    std::cout << "Global generator g initialized." << std::endl;
    pairing_initialized = true;
}


// Evaluate polynomial q(x) at point x=eval_point, given coefficients (q[0] = q(0), q[1]..)
void evaluate_polynomial(ManagedElement& result, const std::vector<ManagedElement>& q_coeffs, int eval_point) {
    if (q_coeffs.empty()) {
        throw std::runtime_error("Polynomial has no coefficients.");
    }
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for evaluate_polynomial");
    result.init_Zr(pairing);
    element_set0(result.get());

    ManagedElement x_pow_i; x_pow_i.init_Zr(pairing);
    ManagedElement term;    term.init_Zr(pairing);
    ManagedElement eval_p_elem; eval_p_elem.init_Zr(pairing);
    element_set_si(eval_p_elem.get(), eval_point);

    element_set1(x_pow_i.get());

    for (size_t i = 0; i < q_coeffs.size(); ++i) {
        // Correctly cast the pointer obtained from decay
        element_mul(term.get(), const_cast<element_s*>(q_coeffs[i].get()), x_pow_i.get());
        element_add(result.get(), result.get(), term.get());

        if (i + 1 < q_coeffs.size()) {
             element_mul(x_pow_i.get(), x_pow_i.get(), eval_p_elem.get());
        }
    }
}


// Calculate Lagrange coefficient Δ_{index_i, S}(0) in Zp
void LagrangeCoeff(ManagedElement& result, int index_i, const std::vector<int>& S_indices) {
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for LagrangeCoeff");
    result.init_Zr(pairing);
    element_set1(result.get());

    ManagedElement num; num.init_Zr(pairing);
    ManagedElement den; den.init_Zr(pairing);
    ManagedElement inv_den; inv_den.init_Zr(pairing);
    ManagedElement term; term.init_Zr(pairing);
    ManagedElement elem_i; elem_i.init_Zr(pairing);
    ManagedElement elem_j; elem_j.init_Zr(pairing);

    element_set_si(elem_i.get(), index_i);

    for (int index_j : S_indices) {
        if (index_i == index_j) continue;

        element_set_si(elem_j.get(), index_j);
        element_neg(num.get(), elem_j.get());
        element_sub(den.get(), elem_i.get(), elem_j.get());
        if (element_is0(den.get())) {
             throw std::runtime_error("Lagrange denominator is zero (duplicate index?)");
        }
        element_invert(inv_den.get(), den.get());
        element_mul(term.get(), num.get(), inv_den.get());
        element_mul(result.get(), result.get(), term.get());
    }
}

// Recursive function for KeyGen polynomial assignment and component calculation
void generate_polynomials_and_components(
    TreeNode* node,
    const ManagedElement& parent_poly_val_at_node_index, // CONST reference
    const MasterKey& mk,
    const PublicKey& pk
) {
    if (!node) return;
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for generate_polynomials");

    node->polynomial_value_at_0.init_Zr(pairing);
    // Correctly cast the pointer obtained from decay
    element_set(node->polynomial_value_at_0.get(), const_cast<element_s*>(parent_poly_val_at_node_index.get()));


    if (node->is_leaf) {
        const std::string& attr = node->attribute;
        auto it_t = mk.t.find(attr);
        if (it_t == mk.t.end()) {
            throw std::runtime_error("Attribute '" + attr + "' not found in Master Key during KeyGen for leaf.");
        }
        const ManagedElement& ti = it_t->second; // ti is const

        ManagedElement inv_ti; inv_ti.init_Zr(pairing);
        ManagedElement exponent; exponent.init_Zr(pairing);

        // Correctly cast the pointer obtained from decay
        element_invert(inv_ti.get(), const_cast<element_s*>(ti.get()));
        element_mul(exponent.get(), node->polynomial_value_at_0.get(), inv_ti.get());

        node->secret_component.init_G1(pairing);
        element_pow_zn(node->secret_component.get(), g, exponent.get());

    } else {
        int degree = node->kx - 1;
        if (degree < 0) {
            throw std::runtime_error("Node threshold kx must be >= 1");
        }

        std::vector<ManagedElement> q_coeffs(degree + 1);
        q_coeffs[0].init_Zr(pairing);
        element_set(q_coeffs[0].get(), node->polynomial_value_at_0.get());

        for (int i = 1; i <= degree; ++i) {
            q_coeffs[i].init_Zr(pairing);
            element_random(q_coeffs[i].get());
        }

        for (auto& child_ptr : node->children) {
            TreeNode* child = child_ptr.get();
            int child_index = child->index_in_parent;
            if (child_index == 0) {
                 throw std::runtime_error("Child index cannot be 0 for polynomial evaluation.");
            }

            ManagedElement qx_at_child_index;
            evaluate_polynomial(qx_at_child_index, q_coeffs, child_index);
            // Pass the non-const qx_at_child_index recursively
            generate_polynomials_and_components(child, qx_at_child_index, mk, pk);
        }
    }
}

// Recursive function for Decryption logic
bool decrypt_node(
    ManagedElement& result,
    const TreeNode* node, // CONST node
    const Ciphertext& ct
) {
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for decrypt_node");
     if (!node) return false;

    if (node->is_leaf) {
        const std::string& attr = node->attribute;
        auto it_ct_E = ct.E.find(attr);
        if (it_ct_E == ct.E.end()) {
            return false;
        }
        const ManagedElement& Ei = it_ct_E->second; // Ei is const
        const ManagedElement& Dx = node->secret_component; // Dx is const

         if (!Dx.initialized) {
             // Suppress warning in normal operation, only enable for deep debug
             // std::cerr << "Warning: Secret component for leaf '" << attr << "' not initialized." << std::endl;
             return false;
         }

        result.init_GT(pairing);
        // Correctly cast the pointers obtained from decay
        pairing_apply(result.get(), const_cast<element_s*>(Dx.get()), const_cast<element_s*>(Ei.get()), pairing);
        return true;

    } else {
        std::vector<std::pair<int, ManagedElement>> valid_child_results;
        valid_child_results.reserve(node->children.size());

        for (const auto& child_ptr : node->children) {
            ManagedElement child_result;
            if (decrypt_node(child_result, child_ptr.get(), ct)) {
                valid_child_results.push_back({child_ptr->index_in_parent, std::move(child_result)});
            }
        }

        if (valid_child_results.size() < static_cast<size_t>(node->kx)) {
            return false;
        }

        std::vector<int> S_indices; S_indices.reserve(node->kx);
        std::vector<ManagedElement> Fz_values; Fz_values.reserve(node->kx);

        for(int i=0; i < node->kx; ++i) {
             S_indices.push_back(valid_child_results[i].first);
             Fz_values.push_back(std::move(valid_child_results[i].second));
        }

        result.init_GT(pairing);
        element_set1(result.get());

        ManagedElement delta_i;
        ManagedElement term;

        for (int i = 0; i < node->kx; ++i) {
            int current_index = S_indices[i];
            const ManagedElement& current_Fz = Fz_values[i]; // Fz is const

            LagrangeCoeff(delta_i, current_index, S_indices);

            term.init_GT(pairing);
            // Correctly cast the pointer obtained from decay
            element_pow_zn(term.get(), const_cast<element_s*>(current_Fz.get()), delta_i.get());
            element_mul(result.get(), result.get(), term.get());
        }
        return true;
    }
}

// --- Main KP-ABE Algorithms (with enhanced output and timing) ---

void Setup(PublicKey& pk, MasterKey& mk, const std::set<std::string>& attributes) {
    auto start = std::chrono::high_resolution_clock::now();
    std::cout << "\n=== Running Setup ===" << std::endl;
    if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for Setup");
    print_attributes(attributes, "Attribute Universe");

    element_random(mk.y.get());
    std::cout << "Generated Master Key component 'y'." << std::endl; // Don't print y itself

    ManagedElement temp_gt; temp_gt.init_GT(pairing);
    int count = 0;
    for (const std::string& attr : attributes) {
        ManagedElement ti; ti.init_Zr(pairing);
        ManagedElement Ti; Ti.init_G1(pairing);
        element_random(ti.get());
        element_pow_zn(Ti.get(), g, ti.get());
        mk.t[attr] = std::move(ti);
        pk.T[attr] = std::move(Ti);
        count++;
    }
    std::cout << "Generated " << count << " Master Key components (t_i) and Public Key components (T_i)." << std::endl;

    pairing_apply(temp_gt.get(), g, g, pairing);
    element_pow_zn(pk.Y.get(), temp_gt.get(), mk.y.get());
    print_element(pk.Y, "Generated Public Key component Y = e(g,g)^y");

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Setup Complete. Duration: " << duration.count() << " ms" << std::endl;
}

SecretKey KeyGeneration(const MasterKey& mk, const PublicKey& pk, std::unique_ptr<TreeNode> access_tree_root) {
     auto start = std::chrono::high_resolution_clock::now();
     std::cout << "\n=== Running Key Generation ===" << std::endl;
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for KeyGen");
    if (!access_tree_root) {
        throw std::runtime_error("Access tree root cannot be null for Key Generation.");
    }
     if (!mk.y.initialized) {
          throw std::runtime_error("Master key 'y' is not initialized.");
     }

    std::cout << "Input Access Policy Tree:" << std::endl;
    print_tree(access_tree_root.get());

    generate_polynomials_and_components(access_tree_root.get(), mk.y, mk, pk);

    // Optionally print generated key components (Dx) - can be verbose
    // std::cout << "Generated Secret Key components (D_x)." << std::endl;

     auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
     std::cout << "Key Generation Complete. Duration: " << duration.count() << " ms" << std::endl;
    return SecretKey(std::move(access_tree_root));
}

Ciphertext Encrypt(const ManagedElement& M, // CONST M
                   const std::set<std::string>& gamma,
                   const PublicKey& pk // CONST pk
                   ) {
    auto start = std::chrono::high_resolution_clock::now();
    std::cout << "\n=== Running Encryption ===" << std::endl;
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for Encrypt");

    print_attributes(gamma, "Encrypting with Attributes (gamma)");
    print_element(M, "Original Message M (in GT)");

    if (!M.initialized) {
         throw std::runtime_error("Message M is not initialized for encryption.");
    }

    Ciphertext ct;
    ct.gamma = gamma;

    ManagedElement s; s.init_Zr(pairing);
    element_random(s.get());
    // std::cout << "Generated random s." << std::endl; // Usually not printed

    ManagedElement Ys; Ys.init_GT(pairing);
    element_pow_zn(Ys.get(), const_cast<element_s*>(pk.Y.get()), s.get());
    element_mul(ct.E_prime.get(), const_cast<element_s*>(M.get()), Ys.get());
    print_element(ct.E_prime, "Ciphertext component E' = M * Y^s");

    int count = 0;
    for (const std::string& attr : gamma) {
        auto it_pk_T = pk.T.find(attr);
        if (it_pk_T == pk.T.end()) {
            // This case should ideally be prevented by checking gamma against universe earlier
            throw std::runtime_error("Attribute '" + attr + "' in gamma not found in Public Key during Encryption.");
        }
        const ManagedElement& Ti = it_pk_T->second;
        ManagedElement Ei; Ei.init_G1(pairing);
        element_pow_zn(Ei.get(), const_cast<element_s*>(Ti.get()), s.get());
        // print_element(Ei, "Ciphertext component E_" + attr); // Can be verbose
        ct.E[attr] = std::move(Ei);
        count++;
    }
     std::cout << "Generated " << count << " Ciphertext components (E_i)." << std::endl;

     auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
     std::cout << "Encryption Complete. Duration: " << duration.count() << " ms" << std::endl;
    return ct;
}

bool Decrypt(ManagedElement& M, // Output M
             const Ciphertext& ct, // CONST ct
             const SecretKey& sk // CONST sk
             ) {
    auto start = std::chrono::high_resolution_clock::now();
    std::cout << "\n=== Running Decryption ===" << std::endl;
     if (!pairing_initialized) throw std::runtime_error("Pairing not initialized for Decrypt");
    if (!sk.root) {
         throw std::runtime_error("Secret key does not contain a valid access tree.");
    }

    print_attributes(ct.gamma, "Decrypting Ciphertext with Attributes");
    std::cout << "Using Secret Key with Access Policy Tree:" << std::endl;
    print_tree(sk.root.get());

    // Optional: Check policy satisfaction beforehand
    bool policy_satisfied = sk.root->check_satisfy(ct.gamma);
    std::cout << "Policy satisfaction check: " << (policy_satisfied ? "SATISFIED" : "NOT SATISFIED") << std::endl;
    if (!policy_satisfied) {
         std::cerr << "Decryption Failed: Ciphertext attributes do not satisfy the key's access policy (pre-check)." << std::endl;
         auto end = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
         std::cout << "Decryption Duration: " << duration.count() << " ms" << std::endl;
         return false;
    }


    ManagedElement A; // To store e(g,g)^(y*s)
    if (decrypt_node(A, sk.root.get(), ct)) {
        print_element(A, "Intermediate result A = e(g,g)^ys");
        ManagedElement inv_A; inv_A.init_GT(pairing);
        element_invert(inv_A.get(), A.get());

        M.init_GT(pairing);
        element_mul(M.get(), const_cast<element_s*>(ct.E_prime.get()), inv_A.get());
        print_element(M, "Decrypted Message M");
        std::cout << "Decryption Successful." << std::endl;

         auto end = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
         std::cout << "Decryption Duration: " << duration.count() << " ms" << std::endl;
        return true;
    } else {
        // This branch might be less likely now due to the pre-check, but good to keep
        std::cerr << "Decryption Failed: DecryptNode recursive call failed (unexpectedly after pre-check passed)." << std::endl;
        M.init_GT(pairing);
        element_set1(M.get()); // Set to identity or some default

         auto end = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
         std::cout << "Decryption Duration: " << duration.count() << " ms" << std::endl;
        return false;
    }
}

// --- Test Case Functions ---

void run_test_case(const std::string& case_name,
                   std::unique_ptr<TreeNode> (*policy_builder)(), // Function pointer to build the tree
                   const std::set<std::string>& encrypt_attrs,
                   bool expected_success,
                   const MasterKey& mk,
                   const PublicKey& pk,
                   const ManagedElement& M_orig)
{
    std::cout << "\n======================================================" << std::endl;
    std::cout << "                TEST CASE: " << case_name << std::endl;
    std::cout << "======================================================" << std::endl;
    std::cout << "--- Test Parameters ---" << std::endl;
    print_attributes(encrypt_attrs, "Encryption Attributes (gamma)");
    std::cout << "Expected Decryption Outcome: " << (expected_success ? "Success" : "Failure") << std::endl;
    std::cout << "Access Policy to be generated by KeyGen:" << std::endl;
    auto temp_policy_tree = policy_builder(); // Build temporary tree just for printing structure
    print_tree(temp_policy_tree.get());
    std::cout << "------------------------" << std::endl;


    // 1. Key Generation for the specific policy
    SecretKey sk = KeyGeneration(mk, pk, policy_builder()); // Build the actual tree for the key

    // 2. Encrypt with the specified attributes
    Ciphertext ct = Encrypt(M_orig, encrypt_attrs, pk);

    // 3. Decrypt
    ManagedElement M_dec;
    bool actual_success = Decrypt(M_dec, ct, sk);

    // 4. Verify Result
    std::cout << "\n--- Test Verification ---" << std::endl;
    bool match = false;
    if (actual_success) {
        match = !element_cmp(M_orig.get(), M_dec.get());
    }

    if (actual_success == expected_success) {
        if (expected_success) { // Expect success, check if message matches
            if (match) {
                 std::cout << "VERDICT: PASSED! Decryption succeeded and message matched." << std::endl;
            } else {
                 std::cout << "VERDICT: FAILED! Decryption succeeded BUT message did NOT match." << std::endl;
            }
        } else { // Expect failure, check it failed
             std::cout << "VERDICT: PASSED! Decryption correctly failed as expected." << std::endl;
        }
    } else {
        if (expected_success) { // Expected success, but it failed
             std::cout << "VERDICT: FAILED! Decryption failed unexpectedly." << std::endl;
        } else { // Expected failure, but it succeeded
             std::cout << "VERDICT: FAILED! Decryption succeeded unexpectedly." << std::endl;
              if (match) {
                 std::cout << "      -> And the message even matched? Problematic!" << std::endl;
              }
        }
    }
    std::cout << "======================================================" << std::endl;
}

// Policy Builder Functions
std::unique_ptr<TreeNode> build_policy_complex_or_and() {
    auto root = std::make_unique<TreeNode>(1, 0, "OR"); // OR gate (k=1)
    auto and1 = std::make_unique<TreeNode>(2, 1, "AND"); // AND gate (k=2)
    and1->addChild(std::make_unique<TreeNode>("STUDENT", 1));
    and1->addChild(std::make_unique<TreeNode>("CS", 2));
    auto and2 = std::make_unique<TreeNode>(2, 2, "AND"); // AND gate (k=2)
    and2->addChild(std::make_unique<TreeNode>("STAFF", 1));
    and2->addChild(std::make_unique<TreeNode>("EE", 2));
    root->addChild(std::move(and1));
    root->addChild(std::move(and2));
    return root;
}

std::unique_ptr<TreeNode> build_policy_simple_and() {
    auto root = std::make_unique<TreeNode>(2, 0, "AND"); // AND gate (k=2)
    root->addChild(std::make_unique<TreeNode>("ADMIN", 1));
    root->addChild(std::make_unique<TreeNode>("CS", 2));
    return root;
}

std::unique_ptr<TreeNode> build_policy_simple_or() {
    auto root = std::make_unique<TreeNode>(1, 0, "OR"); // OR gate (k=1)
    root->addChild(std::make_unique<TreeNode>("ADMIN", 1));
    root->addChild(std::make_unique<TreeNode>("STAFF", 2));
    return root;
}


// --- Main Function ---
int main() {
    try {
        init_pairing(160, 512);

        // 1. Define Attribute Universe
        std::set<std::string> universe = {"STUDENT", "STAFF", "CS", "EE", "ADMIN"};

        // 2. Setup (Run once)
        PublicKey pk;
        MasterKey mk;
        Setup(pk, mk, universe);

        // 3. Define Original Message (Run once)
        ManagedElement M_orig; M_orig.init_GT(pairing);
        element_random(M_orig.get());
        std::cout << "\n=== Original Message Set ===" << std::endl;
        print_element(M_orig, "Original Message M_orig");

        // 4. Run Test Cases

        // --- Test Case Set 1: Complex Policy ---
        run_test_case("Complex Policy 1 (Success Left)", build_policy_complex_or_and, {"STUDENT", "CS", "ADMIN"}, true, mk, pk, M_orig);
        run_test_case("Complex Policy 2 (Success Right)", build_policy_complex_or_and, {"STAFF", "EE"}, true, mk, pk, M_orig);
        run_test_case("Complex Policy 3 (Failure Mixed)", build_policy_complex_or_and, {"STUDENT", "EE"}, false, mk, pk, M_orig);
        run_test_case("Complex Policy 4 (Failure Partial)", build_policy_complex_or_and, {"CS"}, false, mk, pk, M_orig);

        // --- Test Case Set 2: Simple AND Policy ---
        run_test_case("Simple AND 1 (Success Exact)", build_policy_simple_and, {"ADMIN", "CS"}, true, mk, pk, M_orig);
        run_test_case("Simple AND 2 (Success More)", build_policy_simple_and, {"ADMIN", "CS", "STUDENT"}, true, mk, pk, M_orig);
        run_test_case("Simple AND 3 (Failure Partial)", build_policy_simple_and, {"ADMIN"}, false, mk, pk, M_orig);

        // --- Test Case Set 3: Simple OR Policy ---
        run_test_case("Simple OR 1 (Success Left)", build_policy_simple_or, {"ADMIN"}, true, mk, pk, M_orig);
        run_test_case("Simple OR 2 (Success Right)", build_policy_simple_or, {"STAFF", "EE"}, true, mk, pk, M_orig);
        run_test_case("Simple OR 3 (Failure Neither)", build_policy_simple_or, {"EE"}, false, mk, pk, M_orig);


    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        if (pairing_initialized) {
             if(g->field) element_clear(g);
             pairing_clear(pairing);
             pairing_initialized = false;
        }
        return 1;
    }

    if (pairing_initialized) {
        if(g->field) element_clear(g);
        pairing_clear(pairing);
        pairing_initialized = false;
        std::cout << "\nPairing cleared. Exiting." << std::endl;
    }
    return 0;
}
