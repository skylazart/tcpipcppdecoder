#ifndef MOST_POPULAR_H
#define MOST_POPULAR_H

#include <unordered_map>

template<typename T>
class MostPopular {
public:
    MostPopular() : freq_{-1}, popular_{} {
	
    }

public:
    void update(T value) {
	int t = frequency_[value] + 1;
	frequency_[value]++;

	if (t > freq_) {
	    freq_ = t;
	    popular_ = value;
	}
    }

    T get_popular() {
	return popular_;
    }

private:
    int freq_;
    T popular_;
    std::unordered_map<T, int> frequency_;
};

#endif /* MOST_POPULAR_H */
