#include <bits/stdc++.h> // Includes most standard libraries
#include <string>
#include <vector>
#include <algorithm>
using namespace std;


vector<vector<int>> translating_Sudoku_to_Gcol_problem(vector<vector<int>> &grid,vector<pair<int,int>>&clues){
    int n=9;
    vector<vector<int>>adj(n^2+n+1);
    // Each cell is represented as a node in the graph
    // There are 81 cells in a 9x9 Sudoku grid  
    // 9 special node for fixing values of given clues
    for(int i=1;i<=9;i++){
        for(int j=1;j<=9;j++){
            int node_id=(i-1)*9+j;
            int block=3*((i-1)/3)+(j-1)/3;
            for(int col=1,row=1;col<=9;col++,row++){
                // connects to all nodes in same row and column to ensure its value(color) is different from them
                if(col!=j){
                    int neighbor_id=(i-1)*9+col;
                    adj[node_id].push_back(neighbor_id);

                }
                if(row!=i){
                    int neighbor_id=(row-1)*9+j;
                    adj[node_id].push_back(neighbor_id);

                }
            }
            
            for(int r=block/3*3+1;r<=block/3*3+3;r++){
                for(int c=block%3*3+1;c<=block%3*3+3;c++){
                    if(r!=i && c!=j){
                        int neighbor_id=(r-1)*9+c;
                        adj[node_id].push_back(neighbor_id);
                    }
                }
            }
        }
    }
    // clues is a vector of pairs (cell_id,value)
    //each special node represent unique color of 9 colors, so if clue value(color) is x, it is connected to all special nodes except node 81+x so that it can only take color x

    for(auto &clue: clues){
        int cell_id=clue.first;
        int value=clue.second;
        for(int k=1;k<=9;k++){
            if(k!=value){
                int special_node_id=81+ value + 1;
                adj[cell_id].push_back(special_node_id);
                adj[special_node_id].push_back(cell_id);
            }
        }
    }



    

}