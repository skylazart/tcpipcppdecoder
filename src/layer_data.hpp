#ifndef LAYER_DATA_H
#define LAYER_DATA_H

#include <string>
#include <memory>

struct layer_data {
public:
    virtual std::string to_string() = 0;
};

typedef std::shared_ptr<layer_data> layer_data_ptr;

#endif /* LAYER_DATA_H */
