#include <bits/stdc++.h> // Includes most standard libraries
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/sha.h>
#include <random>
#include <asio.hpp> // Asio for networking

// Bring in namespaces
using namespace std;
using asio::ip::tcp;

// Type definitions
#define ll long long
#define ld long double

/*
 * =============================================================================
 * Network Helper Functions
 * =============================================================================
 */

/**
 * @brief Sends the vector of hash commitments to the Verifier.
 * Protocol: [uint32_t count][loop count times: [uint32_t length][data...]]
 */
void send_hash_vector(tcp::socket& socket, const std::vector<std::string>& vec){
    // 1. Send the vector size (the "count")
    uint32_t vector_size = vec.size();
    uint32_t net_vector_size = htonl(vector_size); // Convert to Network Byte Order
    asio::write(socket, asio::buffer(&net_vector_size, sizeof(net_vector_size)));

    // 2. Loop "count" times
    for (const std::string& s : vec) {
        // 2a. Send the string length
        uint32_t string_length = s.length();
        uint32_t net_string_length = htonl(string_length); // Convert to Network Byte Order
        asio::write(socket, asio::buffer(&net_string_length, sizeof(net_string_length)));

        // 2b. Send the string data
        asio::write(socket, asio::buffer(s));
    }
    
    std::cout << "[Prover] Sent " << vector_size << " commitments." << std::endl;
}

/**
 * @brief Receives the edge (u, v) challenge from the Verifier.
 */
pair<int,int> receive_edge(tcp::socket& socket){
    uint32_t net_u, net_v;
    
    asio::read(socket, asio::buffer(&net_u, sizeof(net_u)));
    asio::read(socket, asio::buffer(&net_v, sizeof(net_v)));
    
    int u = ntohl(net_u);
    int v = ntohl(net_v);
    
    cout << "[Prover] Received challenge: Reveal nodes " << u << " and " << v << endl;
    
    // 1. ***FIX***: Added the missing return statement.
    return {u, v};
}

/**
 * @brief Sends the revealed (color, salt) pairs to the Verifier.
 * Protocol: [uint32_t color1][uint32_t salt1_len][salt1_data...][uint32_t color2]...
 */
void send_revealed(tcp::socket& socket, vector<pair<int,string>>& revealed){
    for(auto& p : revealed){
        int color = p.first;
        string rand_str = p.second;
        
        uint32_t net_color = htonl(color);
        asio::write(socket, asio::buffer(&net_color, sizeof(net_color)));
        
        uint32_t str_length = rand_str.length();
        uint32_t net_str_length = htonl(str_length);
        asio::write(socket, asio::buffer(&net_str_length, sizeof(net_str_length)));
        
        asio::write(socket, asio::buffer(rand_str));
    }
    cout << "[Prover] Sent revealed colors and salts." << endl;
}

/*
 * =============================================================================
 * ZKP Logic Functions (Copied from your original program)
 * =============================================================================
 */

/**
 * @brief Prover's logic to create hash commitments
 */
vector<string> commit(vector<int>& color, vector<string>& random_bits){
    vector<string> hash_values(color.size());
    // Loop starts at 1 because graph is 1-indexed
    for(int i = 1; i < color.size(); i++){
        string to_hash = to_string(color[i]) + random_bits[i];
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)to_hash.c_str(), to_hash.size(), hash);
        
        string hash_str;
        for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
            char buf[3];
            sprintf(buf, "%02x", hash[j]);
            hash_str += buf;
        }
        
        // cout << hash_str << endl; // Optional: can be noisy
        hash_values[i] = hash_str;
    }
    return hash_values;
}

/**
 * @brief Prover's logic to prepare the revealed data
 */
vector<pair<int,string>> reveal(pair<int,int> edge, vector<int>& color, vector<string>& random_bits){
    int u = edge.first;
    int v = edge.second;
    
    cout << "[Prover] Revealing: Node " << u << " (Color " << color[u] << "), Node " << v << " (Color " << color[v] << ")" << endl;
   
    vector<pair<int,string>> revealed = {{color[u], random_bits[u]}, {color[v], random_bits[v]}};
    return revealed;
}

/*
 * =============================================================================
 * Main Program
 * =============================================================================
 */

int main(){
    try{
        // 1. Get graph details and secret coloring
        int n, m;
        cout << "[Prover] Please enter graph info (n m): ";
        cin >> n >> m;
        
        vector<vector<int>> adj(n+1);
        vector<vector<int>> edges(m, vector<int>(2));
        vector<int> color(n+1, -1);

        cout << "[Prover] Please enter " << m << " edges (u v):" << endl;
        for(int i = 0; i < m; i++){
            int u, v;
            cin >> u >> v;
            edges[i][0] = u;
            edges[i][1] = v;
            adj[u].push_back(v);
            adj[v].push_back(u);
        }
        
        cout << "[Prover] Please enter the secret 3-coloring (" << n << " colors, 1-indexed):" << endl;
        for(int i = 1; i <= n; i++){
            cin >> color[i]; // reading a valid 3-coloring
        }

        // 2. Connect to the Verifier (Server)
        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        
        // 2. ***FIX***: Changed "local host" to "localhost" (no space)
        auto endpoints = resolver.resolve("localhost", "12345"); // Must match Verifier's port

        tcp::socket socket(io_context);
        asio::connect(socket, endpoints); // Connect to the Verifier

        std::cout << "[Prover] Connected to Verifier!" << std::endl;
        
        // 3. Run the ZKP loop
        int iter = 100;
        random_device rd;
        mt19937 gen(rd());
        
        while(iter--){
            cout << "\n--- [Prover] Round " << (100 - iter) << " ---" << endl;
            
            // Permute colors
            vector<int> perm = {0, 1, 2};
            shuffle(perm.begin(), perm.end(), gen);
            for(int i = 1; i <= n; i++){
                color[i] = perm[color[i]];
            }

            // Generate random salts
            vector<string> random_bits(n+1);
            uniform_int_distribution<> dis(1e8, 1e9);
            for(int i = 1; i <= n; i++){
                random_bits[i] = to_string(dis(gen));
            }

            // Prover commits and sends hashes
            vector<string> hash_values = commit(color, random_bits);
            send_hash_vector(socket, hash_values);

            // Prover receives challenge
            pair<int,int> edge = receive_edge(socket);

            // Prover reveals data for the challenged edge
            vector<pair<int,string>> revealed = reveal(edge, color, random_bits);
            send_revealed(socket, revealed);
        }
        
        // 3. ***FIX***: Loop check changed to iter < 0
        if(iter < 0){
            cout << "\n[Prover] *** PROTOCOL COMPLETED (100 rounds) ***" << endl;
        }
 
    } 
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}

