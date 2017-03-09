#ifndef LIBVMI_REQUEST_H
#define LIBVMI_REQUEST_H

struct request{
    uint64_t type;      // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;  // address to read from OR write to
    uint64_t length;   // number of bytes to read OR write
};

#endif /* LIBVMI_REQUEST_H */
