//! Server pool management with weighted random selection.

use rand::Rng;
use std::sync::RwLock;
use tracing::info;

/// A single upstream server in the pool.
#[derive(Debug, Clone)]
pub struct Server {
    /// Unique identifier (e.g., "blue", "green")
    pub id: String,
    /// Upstream address (host:port, supports hostnames)
    pub addr: String,
    /// Routing weight (0 = no traffic, higher = more traffic)
    pub weight: u32,
}

impl Server {
    /// Create a new server with the given id, address, and weight.
    #[must_use]
    pub fn new(id: impl Into<String>, addr: impl Into<String>, weight: u32) -> Self {
        Self {
            id: id.into(),
            addr: addr.into(),
            weight,
        }
    }
}

/// Thread-safe pool of upstream servers with weighted selection.
pub struct ServerPool {
    servers: RwLock<Vec<Server>>,
}

impl ServerPool {
    /// Create an empty server pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            servers: RwLock::new(Vec::new()),
        }
    }

    /// Register a new server in the pool.
    /// Returns `true` if the server was added, `false` if a server with the same ID already exists.
    pub fn register(&self, server: &Server) -> bool {
        let mut servers = self.servers.write().unwrap();
        if servers.iter().any(|s| s.id == server.id) {
            return false;
        }

        servers.push(server.clone());
        drop(servers);

        info!(
            "Registered server: id = {}, addr = {}, weight = {}",
            server.id, server.addr, server.weight
        );

        true
    }

    /// Deregister a server by ID.
    /// Returns the removed server, or `None` if not found.
    pub fn deregister(&self, id: &str) -> Option<Server> {
        let mut servers = self.servers.write().unwrap();
        servers
            .iter()
            .position(|s| s.id == id)
            .map(|pos| servers.remove(pos))
    }

    /// Update the weight of a server by ID.
    /// Returns the old weight of the server.
    pub fn update_weight(&self, id: &str, weight: u32) -> Option<u32> {
        let mut servers = self.servers.write().unwrap();
        servers.iter_mut().find(|s| s.id == id).map(|s| {
            let old = s.weight;
            s.weight = weight;
            old
        })
    }

    /// List all servers in the pool.
    pub fn list(&self) -> Vec<Server> {
        self.servers.read().unwrap().clone()
    }

    /// Select a server using weighted random selection.
    /// Returns `None` if no servers are available or all weights are zero.
    pub fn select(&self) -> Option<Server> {
        let servers = self.servers.read().unwrap();

        // Calculate total weight
        let total_weight: u32 = servers.iter().map(|s| s.weight).sum();
        if total_weight == 0 {
            return None;
        }

        // Generate random value in [0, total_weight)
        let mut rng = rand::rng();
        let mut random_value = rng.random_range(0..total_weight);

        // Walk servers, subtracting weights until we hit zero
        for server in &*servers {
            if server.weight == 0 {
                continue;
            }
            if random_value < server.weight {
                return Some(server.clone());
            }
            random_value -= server.weight;
        }

        drop(servers);

        // Shouldn't reach here, but return None as fallback
        None
    }
}

impl Default for ServerPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_list() {
        let pool = ServerPool::new();
        let server = Server::new("test", "127.0.0.1:25565", 100);

        assert!(pool.register(&server));
        assert!(!pool.register(&server)); // Duplicate

        let servers = pool.list();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "test");
    }

    #[test]
    fn test_deregister() {
        let pool = ServerPool::new();
        pool.register(&Server::new("test", "127.0.0.1:25565", 100));

        let removed = pool.deregister("test");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, "test");
        assert!(pool.list().is_empty());

        assert!(pool.deregister("nonexistent").is_none());
    }

    #[test]
    fn test_update_weight() {
        let pool = ServerPool::new();
        pool.register(&Server::new("test", "127.0.0.1:25565", 100));

        assert_eq!(pool.update_weight("test", 50), Some(100));
        assert_eq!(pool.list()[0].weight, 50);

        assert_eq!(pool.update_weight("nonexistent", 50), None);
    }

    #[test]
    fn test_select_empty_pool() {
        let pool = ServerPool::new();
        assert!(pool.select().is_none());
    }

    #[test]
    fn test_select_zero_weight() {
        let pool = ServerPool::new();
        pool.register(&Server::new("test", "127.0.0.1:25565", 0));
        assert!(pool.select().is_none());
    }

    #[test]
    fn test_select_single_server() {
        let pool = ServerPool::new();
        pool.register(&Server::new("test", "127.0.0.1:25565", 100));

        // Should always return the single server
        for _ in 0..10 {
            let selected = pool.select();
            assert!(selected.is_some());
            assert_eq!(selected.unwrap().id, "test");
        }
    }

    #[test]
    fn test_weighted_selection_distribution() {
        let pool = ServerPool::new();
        pool.register(&Server::new("high", "127.0.0.1:25565", 90));
        pool.register(&Server::new("low", "127.0.0.1:25566", 10));

        let mut high_count = 0;
        let mut low_count = 0;

        for _ in 0..1000 {
            let selected = pool.select().unwrap();
            if selected.id == "high" {
                high_count += 1;
            } else {
                low_count += 1;
            }
        }

        // High should get roughly 90% of selections (allow some variance)
        let high_ratio = high_count as f64 / 1000.0;
        assert!(
            high_ratio > 0.80 && high_ratio < 0.98,
            "high_ratio: {high_ratio}"
        );

        let low_ratio = low_count as f64 / 1000.0;
        assert!(
            low_ratio > 0.02 && low_ratio < 0.20,
            "low_ratio: {low_ratio}"
        );

        assert_eq!(
            high_count + low_count,
            1000,
            "total count: {high_count} + {low_count}"
        );
    }
}
