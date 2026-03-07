#ifndef WILLOW_LEDGER_HPP
#define WILLOW_LEDGER_HPP

#include <cstdint>
#include <atomic>
#include <thread>
#include <cstring>

#if defined(_WIN32)
    #include <windows.h>
    #include <intrin.h>
    #define HOT_PATH __forceinline
    #define CACHE_LINE 64
#else
    #include <pthread.h>
    #include <sys/mman.h>
    #include <unistd.h>
    #include <sched.h>
    #define HOT_PATH inline __attribute__((always_inline))
    #define CACHE_LINE 64
#endif

// ==================== RESOURCE TYPES (FULL SET) ====================
enum class ResourceType : uint8_t {
    CPU_CYCLE = 0, GPU_CYCLE = 1, RAM_BYTE = 2,
    STORAGE_BYTE = 3, HOT_STORAGE = 4, COLD_STORAGE = 5,
    BANDWIDTH_UP = 6, BANDWIDTH_DOWN = 7,
    TORRENT_PIECE = 8, STREAM_SEGMENT = 9, FILE_CHUNK = 10,
    MUSIC_LICENSE = 11, SOFTWARE_LICENSE = 12, NFT = 13,
    ATTENTION_MINUTE = 14, VALIDATION_VOTE = 15,
    RESERVED1 = 16, RESERVED2 = 17, RESERVED3 = 18
};

// ==================== 32-BYTE ENTRY (FULL METADATA) ====================
struct alignas(CACHE_LINE) Entry {
    // 8 bytes: state + version + retry + checksum
    uint64_t control;  // [state:8, version:8, retry:8, checksum:40]
    
    // 8 bytes: transaction id + timestamp
    uint64_t tx_id;    // [tx_id:48, timestamp:16]
    
    // 8 bytes: participants + resource type
    uint64_t parties;  // [sender:24, receiver:24, resource_type:8, resource_id:8]
    
    // 8 bytes: amount + price + proof
    uint64_t value;    // [amount:24, price:24, proof_token:16]
    
    // Total: 32 bytes - same info as original UltraEntry but packed
    
    HOT_PATH uint32_t get_state() const {
        return (control >> 56) & 0xFF;
    }
    
    HOT_PATH void set_state(uint32_t s) {
        uint64_t mask = ~(0xFFULL << 56);
        control = (control & mask) | (static_cast<uint64_t>(s) << 56);
    }
    
    HOT_PATH uint32_t get_version() const {
        return (control >> 48) & 0xFF;
    }
    
    HOT_PATH void inc_version() {
        uint64_t v = ((control >> 48) & 0xFF) + 1;
        control = (control & ~(0xFFULL << 48)) | (v << 48);
    }
    
    HOT_PATH uint32_t get_retry() const {
        return (control >> 40) & 0xFF;
    }
    
    HOT_PATH uint32_t get_checksum() const {
        return control & 0xFFFFFFFFFFULL;
    }
    
    HOT_PATH bool cas_state(uint32_t expected, uint32_t desired) {
        uint64_t old = control;
        uint64_t fresh = (old & ~(0xFFULL << 56)) | (static_cast<uint64_t>(desired) << 56);
        return __sync_bool_compare_and_swap(&control, old, fresh);
    }
};

// ==================== RESOURCE METADATA (COMPACT) ====================
struct ResourceMeta {
    uint64_t id;           // resource_id
    uint64_t owner;        // owner_id
    uint64_t quantity;     // total_quantity
    uint64_t available;    // available_quantity
    uint64_t price;        // price_per_unit
    uint64_t expiry;       // expiration
    uint32_t flags;        // type + quality (packed)
    uint32_t location;     // location hash
    
    union {
        struct { uint32_t cores; uint32_t clock; uint64_t memory; } compute;
        struct { uint64_t total; uint64_t used; uint32_t iops; } storage;
        struct { uint32_t up; uint32_t down; uint32_t latency; } network;
        struct { uint64_t size; uint32_t pieces; uint32_t seeders; } content;
    };
    
    ResourceMeta() : id(0), owner(0), quantity(0), available(0), 
                      price(0), expiry(0), flags(0), location(0) {
        __builtin_memset(&compute, 0, sizeof(compute));
    }
};

// ==================== BATCH TRANSACTION ====================
struct BatchTx {
    uint64_t sender;      // 20 bits
    uint64_t receiver;    // 20 bits
    uint64_t resource_id; // 20 bits
    uint64_t amount;      // 24 bits
    uint64_t price;       // 24 bits
    uint64_t proof;       // 32 bits
    ResourceType type;    // 8 bits
    uint8_t padding[7];
} __attribute__((packed));

// ==================== LOCK-FREE RING BUFFER ====================
template<typename T, size_t N>
class Ring {
    static_assert((N & (N - 1)) == 0, "Ring size must be power of two");
    
    alignas(CACHE_LINE) std::atomic<size_t> head{0};
    alignas(CACHE_LINE) std::atomic<size_t> tail{0};
    T data[N];
    
public:
    HOT_PATH bool push(const T& item) {
        size_t h = head.load(std::memory_order_relaxed);
        size_t n = (h + 1) & (N - 1);
        
        if (n == tail.load(std::memory_order_acquire))
            return false;
            
        data[h] = item;
        head.store(n, std::memory_order_release);
        return true;
    }
    
    HOT_PATH bool pop(T& item) {
        size_t t = tail.load(std::memory_order_relaxed);
        if (t == head.load(std::memory_order_acquire))
            return false;
            
        __builtin_prefetch(&data[(t + 1) & (N - 1)], 0, 3);
        item = data[t];
        tail.store((t + 1) & (N - 1), std::memory_order_release);
        return true;
    }
    
    HOT_PATH size_t pop_batch(T* items, size_t max) {
        size_t t = tail.load(std::memory_order_relaxed);
        size_t h = head.load(std::memory_order_acquire);
        size_t avail = (h - t) & (N - 1);
        size_t take = avail < max ? avail : max;
        
        for (size_t i = 0; i < take; ++i) {
            if (i + 4 < take)
                __builtin_prefetch(&data[(t + i + 4) & (N - 1)], 0, 0);
            items[i] = data[(t + i) & (N - 1)];
        }
        
        tail.store((t + take) & (N - 1), std::memory_order_release);
        return take;
    }
};

// ==================== HASH ENGINE ====================
struct Hash {
    static HOT_PATH uint64_t fnv1a(const void* data, size_t len) {
        uint64_t h = 0xcbf29ce484222325ULL;
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        
        for (size_t i = 0; i < len; ++i) {
            h ^= bytes[i];
            h *= 0x100000001b3ULL;
        }
        return h;
    }
    
    static HOT_PATH uint32_t crc32_simple(uint64_t a, uint64_t b, double c, uint64_t d) {
        uint64_t tmp;
        __builtin_memcpy(&tmp, &c, sizeof(c));
        return static_cast<uint32_t>(a ^ b ^ tmp ^ d);
    }
};

// ==================== SHARD STATS ====================
struct alignas(CACHE_LINE) ShardStats {
    uint64_t total_tx{0};
    uint64_t successful_tx{0};
    uint64_t failed_tx{0};
    uint64_t disputed_tx{0};
    uint64_t total_volume{0};
    uint64_t latency_sum{0};
    uint64_t latency_min{1000000};
    uint64_t latency_max{0};
    uint64_t start_cycles{0};
    
    HOT_PATH void record_latency(uint64_t cycles) {
        latency_sum += cycles;
        total_tx++;
        if (cycles < latency_min) latency_min = cycles;
        if (cycles > latency_max) latency_max = cycles;
    }
};

// ==================== LEDGER SHARD ====================
class alignas(CACHE_LINE) Shard {
    static constexpr size_t SHARD_SIZE = 1 << 18;  // 262k entries
    static constexpr size_t MASK = SHARD_SIZE - 1;
    static constexpr size_t MAX_RETRIES = 100;
    static constexpr size_t BATCH_SIZE = 32;
    static constexpr uint64_t VERIFY_WINDOW = 5000000; // 5ms in cycles @3GHz
    
    Entry* entries;
    
    alignas(CACHE_LINE) std::atomic<size_t> write_pos{0};
    alignas(CACHE_LINE) std::atomic<size_t> verify_pos{0};
    alignas(CACHE_LINE) std::atomic<size_t> dispute_pos{0};
    
    // Resource catalog (fixed size for now)
    static constexpr size_t MAX_RESOURCES = 1024;
    ResourceMeta resources[MAX_RESOURCES];
    std::atomic<size_t> resource_count{0};
    
    // Per-shard stats
    ShardStats stats;
    
    // Batch buffers
    Entry batch_buffer[BATCH_SIZE];
    
public:
    Shard() {
        // Huge page allocation
        size_t bytes = sizeof(Entry) * SHARD_SIZE;
#ifdef _WIN32
        entries = (Entry*)VirtualAlloc(NULL, bytes, 
                                        MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
                                        PAGE_READWRITE);
        if (!entries)
            entries = (Entry*)VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
#else
        entries = (Entry*)mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                -1, 0);
        if (entries == MAP_FAILED)
            entries = (Entry*)mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
        __builtin_memset(entries, 0, bytes);
        __builtin_memset(resources, 0, sizeof(resources));
        stats.start_cycles = __rdtsc();
    }
    
    ~Shard() {
#ifdef _WIN32
        VirtualFree(entries, 0, MEM_RELEASE);
#else
        munmap(entries, sizeof(Entry) * SHARD_SIZE);
#endif
    }
    
    // ========== CORE PUSH ==========
    HOT_PATH bool push(uint64_t tx_id, uint64_t sender, uint64_t receiver,
                        ResourceType type, uint64_t res_id,
                        double amount, uint64_t price,
                        uint64_t proof_token) {
        
        size_t idx = write_pos.fetch_add(1, std::memory_order_acq_rel) & MASK;
        Entry* e = &entries[idx];
        
        uint64_t start = __rdtsc();
        
        for (size_t retry = 0; retry < MAX_RETRIES; ++retry) {
            if (e->cas_state(0, 1)) {
                // Fill entry
                e->tx_id = (tx_id << 16) | (start & 0xFFFF);
                e->parties = (sender << 24) | (receiver << 0) | 
                            (static_cast<uint64_t>(type) << 48) |
                            ((res_id & 0xFF) << 56);
                
                uint64_t amount_fixed;
                __builtin_memcpy(&amount_fixed, &amount, sizeof(amount));
                e->value = ((amount_fixed & 0xFFFFFF) << 40) |
                          ((price & 0xFFFFFF) << 16) |
                          (proof_token & 0xFFFF);
                
                e->inc_version();
                
                // Calculate checksum
                uint32_t cs = Hash::crc32_simple(sender, receiver, amount, price);
                e->control = (e->control & 0xFFFFFFFFFFFFFFULL) | 
                            (static_cast<uint64_t>(cs) << 24);
                
                std::atomic_thread_fence(std::memory_order_release);
                e->set_state(2); // ready
                
                uint64_t cycles = __rdtsc() - start;
                stats.record_latency(cycles);
                stats.total_volume += price;
                
                return true;
            }
            
            // Backoff
            if (retry < 10) _mm_pause();
            else if (retry < 50) std::this_thread::yield();
        }
        
        stats.failed_tx++;
        return false;
    }
    
    // ========== BATCH PUSH ==========
    size_t push_batch(const BatchTx* txs, size_t count) {
        size_t start = write_pos.fetch_add(count, std::memory_order_acq_rel);
        size_t success = 0;
        uint64_t start_cycles = __rdtsc();
        
        for (size_t i = 0; i < count; ++i) {
            size_t idx = (start + i) & MASK;
            Entry* e = &entries[idx];
            
            if (e->cas_state(0, 1)) {
                const BatchTx& tx = txs[i];
                
                e->tx_id = (generate_id() << 16) | (start_cycles & 0xFFFF);
                e->parties = (tx.sender << 24) | (tx.receiver << 0) |
                            (static_cast<uint64_t>(tx.type) << 48) |
                            ((tx.resource_id & 0xFF) << 56);
                
                uint64_t amount_fixed;
                __builtin_memcpy(&amount_fixed, &tx.amount, sizeof(tx.amount));
                e->value = ((amount_fixed & 0xFFFFFF) << 40) |
                          ((tx.price & 0xFFFFFF) << 16) |
                          (tx.proof & 0xFFFF);
                
                e->inc_version();
                
                uint32_t cs = Hash::crc32_simple(tx.sender, tx.receiver, 
                                                   tx.amount, tx.price);
                e->control = (e->control & 0xFFFFFFFFFFFFFFULL) | 
                            (static_cast<uint64_t>(cs) << 24);
                
                std::atomic_thread_fence(std::memory_order_release);
                e->set_state(2);
                
                success++;
                stats.total_tx++;
                stats.total_volume += tx.price;
            }
        }
        
        uint64_t cycles = __rdtsc() - start_cycles;
        stats.latency_sum += cycles;
        return success;//Luhana!
    }
    
    // ========== READ OPERATIONS ==========
    size_t read_batch(Entry* out, size_t max, bool consume = true) {
        size_t v = verify_pos.load(std::memory_order_relaxed);
        size_t w = write_pos.load(std::memory_order_acquire);
        size_t avail = w - v;
        size_t to_read = avail < max ? avail : max;
        size_t read = 0;
        
        for (size_t i = 0; i < to_read; ++i) {
            size_t idx = (v + i) & MASK;
            
            if (i + 4 < to_read)
                __builtin_prefetch(&entries[(v + i + 4) & MASK], 0, 0);
            
            Entry& e = entries[idx];
            if (e.get_state() >= 2) {
                out[read++] = e;
                if (consume) e.set_state(0);
            }
        }
        
        if (consume)
            verify_pos.fetch_add(to_read, std::memory_order_release);
        
        return read;
    }
    
    size_t read_by_type(Entry* out, size_t max, ResourceType type) {
        size_t v = verify_pos.load(std::memory_order_relaxed);
        size_t w = write_pos.load(std::memory_order_acquire);
        size_t to_check = (w - v) < (max * 2) ? (w - v) : (max * 2);
        size_t read = 0;
        
        for (size_t i = 0; i < to_check && read < max; ++i) {
            size_t idx = (v + i) & MASK;
            Entry& e = entries[idx];
            
            ResourceType t = static_cast<ResourceType>((e.parties >> 48) & 0xFF);
            if (t == type && e.get_state() >= 2) {
                out[read++] = e;
            }
        }
        
        return read;
    }
    
    // ========== VERIFICATION ==========
    void verify_pending() {
        size_t v = verify_pos.load(std::memory_order_relaxed);
        size_t w = write_pos.load(std::memory_order_acquire);
        uint64_t now = __rdtsc();
        
        while (v < w && (v - verify_pos.load(std::memory_order_relaxed)) < BATCH_SIZE) {
            size_t idx = v & MASK;
            Entry& e = entries[idx];
            
            uint32_t state = e.get_state();
            if (state == 2) { // ready
                bool valid = verify_entry(e, now);
                
                if (valid) {
                    e.set_state(3); // verified
                    stats.successful_tx++;
                } else {
                    e.set_state(5); // disputed
                    stats.disputed_tx++;
                }
            }
            v++;
        }
        
        verify_pos.fetch_add(v - verify_pos.load(std::memory_order_relaxed), 
                             std::memory_order_release);
    }
    
    // ========== DISPUTES ==========
    size_t get_disputed(Entry* out, size_t max) {
        size_t d = dispute_pos.load(std::memory_order_relaxed);
        size_t v = verify_pos.load(std::memory_order_acquire);
        size_t avail = v - d;
        size_t to_read = avail < max ? avail : max;
        size_t read = 0;
        
        for (size_t i = 0; i < to_read; ++i) {
            size_t idx = (d + i) & MASK;
            Entry& e = entries[idx];
            
            if (e.get_state() == 5) { // disputed
                out[read++] = e;
            }
        }
        
        dispute_pos.fetch_add(to_read, std::memory_order_release);
        return read;
    }
    
    // ========== RESOURCE MANAGEMENT ==========
    bool register_resource(uint64_t id, const ResourceMeta& meta) {
        size_t idx = resource_count.fetch_add(1, std::memory_order_acq_rel);
        if (idx >= MAX_RESOURCES) return false;
        
        resources[idx] = meta;
        resources[idx].id = id;
        return true;
    }
    
    bool update_availability(uint64_t id, int64_t delta) {
        for (size_t i = 0; i < resource_count.load(std::memory_order_acquire); ++i) {
            if (resources[i].id == id) {
                uint64_t old = resources[i].available;
                uint64_t fresh = old + delta;
                if (delta < 0 && fresh > old) return false; // underflow
                resources[i].available = fresh;
                return true;
            }
        }
        return false;
    }
    
    ResourceMeta* get_resource(uint64_t id) {
        for (size_t i = 0; i < resource_count.load(std::memory_order_acquire); ++i) {
            if (resources[i].id == id)
                return &resources[i];
        }
        return nullptr;
    }
    
    size_t get_available(ResourceType type, ResourceMeta* out, size_t max) {
        size_t found = 0;
        size_t count = resource_count.load(std::memory_order_acquire);
        
        for (size_t i = 0; i < count && found < max; ++i) {
            ResourceType t = static_cast<ResourceType>(resources[i].flags & 0xFF);
            if (t == type && resources[i].available > 0) {
                out[found++] = resources[i];
            }
        }
        
        return found;
    }
    
    // ========== STATISTICS ==========
    ShardStats get_stats() const { return stats; }
    
    double throughput() {
        uint64_t now = __rdtsc();
        uint64_t elapsed = now - stats.start_cycles;
        double seconds = elapsed / 3.3e9; // assume 3.3GHz
        return stats.total_tx / seconds;
    }

private:
    bool verify_entry(const Entry& e, uint64_t now) {
        // Check deadline (timestamp in low 16 bits of tx_id)
        uint64_t timestamp = e.tx_id & 0xFFFF;
        uint64_t tx_cycles = (e.tx_id >> 16) << 16 | timestamp;
        if (now - tx_cycles > VERIFY_WINDOW)
            return false;
        
        // Verify checksum
        uint64_t sender = (e.parties >> 24) & 0xFFFFFF;
        uint64_t receiver = e.parties & 0xFFFFFF;
        double amount;
        uint64_t amount_bits = (e.value >> 40) & 0xFFFFFF;
        __builtin_memcpy(&amount, &amount_bits, sizeof(amount));
        uint64_t price = (e.value >> 16) & 0xFFFFFF;
        
        uint32_t expected = Hash::crc32_simple(sender, receiver, amount, price);
        if (expected != (e.control >> 24))
            return false;
        
        // Verify resource availability
        uint64_t res_id = (e.parties >> 56) & 0xFF;
        ResourceMeta* res = get_resource(res_id);
        if (res) {
            uint64_t amount_needed = (e.value >> 40) & 0xFFFFFF;
            if (amount_needed > res->available)
                return false;
            update_availability(res_id, -static_cast<int64_t>(amount_needed));
        }
        
        return true;
    }
    
    static uint64_t generate_id() {
        static std::atomic<uint64_t> counter{0};
        return counter.fetch_add(1, std::memory_order_relaxed);
    }
};

// ==================== MAIN LEDGER ====================
class Willow {
    static constexpr size_t MAX_SHARDS = 64;
    static constexpr size_t TX_QUEUE_SIZE = 1 << 20;
    
    Shard* shards[MAX_SHARDS];
    Ring<BatchTx, TX_QUEUE_SIZE> tx_queue;
    
    size_t num_shards;
    std::atomic<size_t> next_shard{0};
    std::atomic<bool> running{true};
    std::thread workers[MAX_SHARDS];
    std::thread verification_threads[MAX_SHARDS];
    
    // Global state
    struct alignas(CACHE_LINE) {
        uint64_t total_tx{0};
        uint64_t total_vol{0};
        uint64_t active_users{0};
        uint64_t start_cycles{0};
    } global;
    
    // User registry (simplified - fixed size)
    struct User {
        uint64_t id;
        uint64_t balance;
        char name[32];
    };
    static constexpr size_t MAX_USERS = 10000;
    User users[MAX_USERS];
    std::atomic<size_t> user_count{0};
    
public:
    Willow() {
        num_shards = std::thread::hardware_concurrency();
        if (num_shards > MAX_SHARDS) num_shards = MAX_SHARDS;
        
        for (size_t i = 0; i < num_shards; ++i) {
            shards[i] = new Shard();
        }
        
        __builtin_memset(users, 0, sizeof(users));
        global.start_cycles = __rdtsc();
        
        // Start worker threads
        for (size_t i = 0; i < num_shards; ++i) {
            workers[i] = std::thread([this, i] { worker_main(i); });
            verification_threads[i] = std::thread([this, i] { verifier_main(i); });
            pin_thread(workers[i], i);
            pin_thread(verification_threads[i], i);
        }
    }
    
    ~Willow() {
        running = false;
        for (size_t i = 0; i < num_shards; ++i) {
            if (workers[i].joinable()) workers[i].join();
            if (verification_threads[i].joinable()) verification_threads[i].join();
            delete shards[i];
        }
    }
    
    // ========== CORE API ==========
    HOT_PATH bool send(uint64_t from, uint64_t to, 
                        ResourceType type, uint64_t resource_id,
                        double amount, uint64_t price,
                        uint64_t proof, int hint = -1) {
        
        BatchTx tx;
        tx.sender = from;
        tx.receiver = to;
        tx.resource_id = resource_id;
        tx.amount = amount;
        tx.price = price;
        tx.proof = proof;
        tx.type = type;
        
        if (!tx_queue.push(tx))
            return false;
        
        global.total_tx++;
        global.total_vol += price;
        return true;
    }
    
    // Simplified version for backward compatibility
    HOT_PATH void send(uint64_t from, uint64_t to, double amount, int hint) {
        send(from, to, ResourceType::CPU_CYCLE, 0, amount, 
             static_cast<uint64_t>(amount), 0, hint);
    }
    
    // ========== BATCH API ==========
    size_t send_batch(const BatchTx* txs, size_t count) {
        size_t sent = 0;
        for (size_t i = 0; i < count && sent < 1024; ++i) {
            if (tx_queue.push(txs[i]))
                sent++;
            else
                break;
        }
        
        global.total_tx += sent;
        for (size_t i = 0; i < sent; ++i)
            global.total_vol += txs[i].price;
        
        return sent;
    }
    
    // ========== READ OPERATIONS ==========
    size_t read(Entry* out, size_t max, bool consume = true, int shard = -1) {
        if (shard >= 0 && shard < static_cast<int>(num_shards)) {
            return shards[shard]->read_batch(out, max, consume);
        }
        
        size_t total = 0;
        for (size_t i = 0; i < num_shards && total < max; ++i) {
            total += shards[i]->read_batch(out + total, max - total, consume);
        }
        return total;
    }
    
    size_t read_by_type(Entry* out, size_t max, ResourceType type) {
        size_t total = 0;
        for (size_t i = 0; i < num_shards && total < max; ++i) {
            total += shards[i]->read_by_type(out + total, max - total, type);
        }
        return total;
    }
    
    // ========== USER MANAGEMENT ==========
    uint64_t register_user(const char* name) {
        size_t idx = user_count.fetch_add(1, std::memory_order_acq_rel);
        if (idx >= MAX_USERS) return 0;
        
        uint64_t id = generate_user_id();
        users[idx].id = id;
        users[idx].balance = 1000; // starting balance
        __builtin_strncpy(users[idx].name, name, 31);
        users[idx].name[31] = '\0';
        
        global.active_users++;
        return id;
    }
    
    bool update_balance(uint64_t user_id, int64_t delta) {
        for (size_t i = 0; i < user_count.load(std::memory_order_acquire); ++i) {
            if (users[i].id == user_id) {
                int64_t new_bal = static_cast<int64_t>(users[i].balance) + delta;
                if (new_bal >= 0) {
                    users[i].balance = new_bal;
                    return true;
                }
                return false;
            }
        }
        return false;
    }
    
    uint64_t get_balance(uint64_t user_id) {
        for (size_t i = 0; i < user_count.load(std::memory_order_acquire); ++i) {
            if (users[i].id == user_id)
                return users[i].balance;
        }
        return 0;
    }
    
    // ========== RESOURCE MANAGEMENT ==========
    bool register_resource(uint64_t id, const ResourceMeta& meta) {
        bool ok = true;
        for (size_t i = 0; i < num_shards; ++i) {
            ok &= shards[i]->register_resource(id, meta);
        }
        return ok;
    }
    
    size_t find_resources(ResourceType type, ResourceMeta* out, size_t max) {
        size_t total = 0;
        for (size_t i = 0; i < num_shards && total < max; ++i) {
            total += shards[i]->get_available(type, out + total, max - total);
        }
        return total;
    }
    
    // ========== DISPUTES ==========
    size_t get_disputed(Entry* out, size_t max) {
        size_t total = 0;
        for (size_t i = 0; i < num_shards && total < max; ++i) {
            total += shards[i]->get_disputed(out + total, max - total);
        }
        return total;
    }
    
    // ========== STATISTICS ==========
    struct GlobalStats {
        uint64_t total_tx;
        uint64_t successful_tx;
        uint64_t failed_tx;
        uint64_t disputed_tx;
        uint64_t total_volume;
        double avg_throughput;
        double instant_throughput;
        double avg_latency_ns;
        double min_latency_ns;
        double max_latency_ns;
        size_t active_shards;
        uint64_t active_users;
        double uptime;
        size_t cores;
    };
    
    GlobalStats stats() {
        GlobalStats s{};
        uint64_t total_latency = 0;
        uint64_t total_tx_count = 0;
        
        for (size_t i = 0; i < num_shards; ++i) {
            auto ss = shards[i]->get_stats();
            s.total_tx += ss.total_tx;
            s.successful_tx += ss.successful_tx;
            s.failed_tx += ss.failed_tx;
            s.disputed_tx += ss.disputed_tx;
            s.total_volume += ss.total_volume;
            
            total_latency += ss.latency_sum;
            total_tx_count += ss.total_tx;
            
            if (ss.latency_min < s.min_latency_ns) 
                s.min_latency_ns = ss.latency_min;
            if (ss.latency_max > s.max_latency_ns) 
                s.max_latency_ns = ss.latency_max;
        }
        
        s.avg_latency_ns = total_tx_count ? 
            static_cast<double>(total_latency) / total_tx_count : 0;
        s.active_shards = num_shards;
        s.active_users = global.active_users;
        
        uint64_t now = __rdtsc();
        double secs = (now - global.start_cycles) / 3.3e9;
        s.uptime = secs;
        s.avg_throughput = s.total_tx / secs;
        s.cores = num_shards;
        
        // Calculate instant throughput
        static uint64_t last_tx = 0;
        static uint64_t last_cycles = global.start_cycles;
        uint64_t tx_now = s.total_tx;
        uint64_t cycles_elapsed = now - last_cycles;
        
        if (cycles_elapsed > 3300000000) { // ~1 second
            s.instant_throughput = static_cast<double>(tx_now - last_tx) * 
                                   3.3e9 / cycles_elapsed;
            last_tx = tx_now;
            last_cycles = now;
        }
        
        return s;
    }
    
    void print_report() {
        auto s = stats();
        
        printf("\n🌿  Willow Ledger Report\n");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf(" 📊 Transactions: %'16llu total\n", s.total_tx);
        printf("    ✅ %'16llu successful\n", s.successful_tx);
        printf("    ❌ %'16llu failed\n", s.failed_tx);
        printf("    ⚠️  %'16llu disputed\n", s.disputed_tx);
        printf(" 💰 Volume:      %'16llu\n", s.total_volume);
        printf(" ⚡ Latency:     %'9.2f ns avg", s.avg_latency_ns * 0.3); // cycles to ns @3.3GHz
        printf(" (min %'.0f, max %'.0f)\n", s.min_latency_ns * 0.3, s.max_latency_ns * 0.3);
        printf(" 📈 Throughput:  %'9.2f tx/s avg", s.avg_throughput);
        printf(" (now %'.2f)\n", s.instant_throughput);
        printf(" 👥 Users:       %'16llu active\n", s.active_users);
        printf(" 🎯 Shards:      %'16zu\n", s.active_shards);
        printf(" 🕒 Uptime:      %'9.2f seconds\n", s.uptime);
        printf(" 💻 Cores:       %'16zu\n", s.cores);
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }
    
    size_t shard_count() const { return num_shards; }

private:
    void worker_main(size_t id) {
        Shard* shard = shards[id];
        BatchTx batch[32];
        Entry results[64];
        //Oriole 
        while (running) {
            // Process incoming transactions
            size_t got = tx_queue.pop_batch(batch, 32);
            if (got) {
                shard->push_batch(batch, got);
            }
            
            // Process completed
            size_t ready = shard->read_batch(results, 64, false);
            if (ready) {
                // Could do post-processing here
            }
            
            if (!got && !ready) {
                _mm_pause();
            }
        }
    }
    
    void verifier_main(size_t id) {
        Shard* shard = shards[id];
        while (running) {
            shard->verify_pending();
            _mm_pause();
        }
    }
    
    static void pin_thread(std::thread& t, size_t core) {
#ifdef _WIN32
        SetThreadAffinityMask(t.native_handle(), 1ULL << core);
#else
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(core, &set);
        pthread_setaffinity_np(t.native_handle(), sizeof(set), &set);
#endif
    }
    
    static uint64_t generate_user_id() {
        static std::atomic<uint64_t> counter{1000};
        return counter.fetch_add(1, std::memory_order_relaxed);
    }
};

#endif // WILLOW_LEDGER_HPP