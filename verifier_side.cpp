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
 * @brief Helper function to read an exact number of bytes from a socket
 * @param socket The socket to read from
 * @param length The exact number of bytes to read
 * @return A std::string containing the data
 */
std::string read_data(tcp::socket& socket, size_t length) {
    std::string data(length, '\0'); // Create a string of the right size
    // asio::read will block until 'length' bytes are received
    asio::read(socket, asio::buffer(data)); 
    return data;
}

/**
 * @brief Receives the vector of hash commitments from the Prover.
 * Protocol: [uint32_t count][loop count times: [uint32_t length][data...]]
 */
vector<string> recieve_hash_values(tcp::socket& socket){
    // 1. Read the vector size (the "count")
    uint32_t vector_size_net; // Network byte order
    asio::read(socket, asio::buffer(&vector_size_net, sizeof(vector_size_net)));
    uint32_t vector_size = ntohl(vector_size_net); // Convert to Host byte order

    std::vector<std::string> vec;
    vec.reserve(vector_size); // Reserve space for efficiency

    // 2. Loop "count" times
    for (size_t i = 0; i < vector_size; ++i) {
        // 2a. Read the string length
        uint32_t string_length_net;
        asio::read(socket, asio::buffer(&string_length_net, sizeof(string_length_net)));
        uint32_t string_length = ntohl(string_length_net); // Convert to Host byte order

        // 2b. Read the string data
        vec.push_back(read_data(socket, string_length));
    }

    std::cout << "[Verifier] Received " << vector_size << " commitments." << std::endl;
    return vec;
}

/**
 * @brief Sends the chosen edge (u, v) to the Prover as the challenge.
 */
void send_edge(tcp::socket& socket, pair<int,int> edge){
    // Convert to network-safe 32-bit integers
    uint32_t u = edge.first;
    uint32_t v = edge.second;

    uint32_t net_u = htonl(u);
    uint32_t net_v = htonl(v);
    
    asio::write(socket, asio::buffer(&net_u, sizeof(net_u)));
    asio::write(socket, asio::buffer(&net_v, sizeof(net_v)));
    
    cout << "[Verifier] Sent challenge: Reveal nodes " << u << " and " << v << endl;
}

/**
 * @brief Receives the revealed (color, salt) pairs from the Prover.
 * Protocol: [uint32_t color1][uint32_t salt1_len][salt1_data...][uint32_t color2]...
 */
void receive_revealed(tcp::socket& socket, vector<pair<int,string>>& revealed){
    // We clear the vector first, just in case
    revealed.clear(); 
    
    for(int i = 0; i < 2; i++){
        uint32_t color_net;
        asio::read(socket, asio::buffer(&color_net, sizeof(color_net)));
        int color = ntohl(color_net);

        uint32_t str_length_net;
        asio::read(socket, asio::buffer(&str_length_net, sizeof(str_length_net)));
        uint32_t str_length = ntohl(str_length_net);

        string rand_str = read_data(socket, str_length);
        
        revealed.push_back({color, rand_str});
    }
    cout << "[Verifier] Received revealed colors and salts." << endl;
}

/*
 * =============================================================================
 * ZKP Logic Functions (Copied from your original program)
 * =============================================================================
 */

/**
 * @brief Verifier's logic to select a random edge
 */
pair<int,int> challenge(vector<string>& hash_values, vector<vector<int>>& edges){
    // verifier randomly selects an edge and asks prover to reveal colors of the two nodes
    int random_edge = rand() % edges.size();
    int u = edges[random_edge][0];
    int v = edges[random_edge][1];
    return {u,v};
}

/**
 * @brief Verifier's logic to check the revealed data
 */
bool verify(vector<pair<int,string>>& revealed, vector<string>& hash_values, pair<int,int> edge){
    int u = edge.first;
    int v = edge.second;
    
    // recompute hash values and check if they match
    for(int i = 0; i < 2; i++){
        int node = (i == 0) ? u : v;
        string to_hash = to_string(revealed[i].first) + revealed[i].second;
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)to_hash.c_str(), to_hash.size(), hash);
        
        string hash_str;
        for(int j = 0; j < SHA256_DIGEST_LENGTH; j++){
            char buf[3];
            sprintf(buf, "%02x", hash[j]);
            hash_str += buf;
        }

        // CRITICAL: Check the hash against the correct index
        if(hash_str != hash_values[node]){
            cout << "[Verifier] Hash values do not match for node " << node << "!" << endl;
            return false;
        }
    }
    
    // check if colors are different
    if(revealed[0].first == revealed[1].first){
        cout << "[Verifier] Colors are same!" << endl;
        return false;
    }
    
    cout << "[Verifier] Verification successful for this round!" << endl;
    return true;
}

/*
 * =============================================================================
 * Main Program
 * =============================================================================
 */

int main(){
    try{
        // 1. ***FIX***: All Asio setup code MUST be inside a function like main().
        asio::io_context My_computer;
        // Listen on port 12345
        tcp::acceptor acceptor(My_computer, tcp::endpoint(tcp::v4(), 12345)); 

        cout << "[Verifier] Waiting for connection from Prover on port 12345..." << endl;
        
        // 2. ***FIX***: Create socket and accept connection inside main.
        tcp::socket socket(My_computer);
        acceptor.accept(socket); // This line will pause until Prover connects
        
        cout << "[Verifier] Connected to Prover!" << endl;

        // 3. Get graph details (Verifier only needs graph structure)
        int n, m;
        cout << "[Verifier] Please enter graph info (n m): ";
        cin >> n >> m;
        
        vector<vector<int>> adj(n+1);
        vector<vector<int>> edges(m, vector<int>(2));

        cout << "[Verifier] Please enter " << m << " edges (u v):" << endl;
        for(int i = 0; i < m; i++){
            int u, v;
            cin >> u >> v;
            edges[i][0] = u;
            edges[i][1] = v;
            adj[u].push_back(v);
            adj[v].push_back(u);
        }
        
        // 4. Run the ZKP loop
        int iter = 100;
        
        while(iter--){
            cout << "\n--- [Verifier] Round " << (100 - iter) << " ---" << endl;
            
            // Verifier receives hash values from prover
            // 5. ***FIX***: Removed duplicate call to recieve_hash_values
            vector<string> hash_values = recieve_hash_values(socket);
            
            // Verifier challenges prover to reveal colors of two nodes
            pair<int,int> edge = challenge(hash_values, edges);
            send_edge(socket, edge);
            
            // Verifier receives revealed colors and salts
            vector<pair<int,string>> revealed;
            
            // 6. ***FIX***: `receive_revealed` modifies the vector by reference.
            //    The old call `revealed = receive_revealed(socket)` was a compiler error.
            receive_revealed(socket, revealed);
            
            // Verifier verifies the revealed colors and salts
            bool flag = verify(revealed, hash_values, edge);

            if(!flag){
                cout << "[Verifier] *** VERIFICATION FAILED! ***" << endl;
                return 0; // Exit program
            }
        }
        
        if(iter < 0){ // Check if loop finished (iter will be -1)
            cout << "\n[Verifier] *** VERIFICATION SUCCESSFUL (100 rounds) ***" << endl;
        }

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
