#include <vector>
#include <iostream>

int main() {
    std::vector<int> vec = {};
    int sum = 0;

    for (int i = 0; i < 1000000; i++) {
        vec.push_back(i);
        sum += i;
    }

    std::cout << sum << std::endl;

    return 0;
}