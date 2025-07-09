#include <bits/stdc++.h>
using namespace std;
int q[10000000];
int main(){
    int n,sum=0;
    cin>>n; 
    for (int i=1;i<=n;i++)
        for (int j=1;j<=n;j++)
            for (int k=1;k<=n;k++){
                q[i^j^k]=sum++;
            }
    cout<<q[sum]<<endl;
}