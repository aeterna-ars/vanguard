#[cfg(feature = "userspace")]
use super::*;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct SkGlobalStats {
    pub total: u64,
    pub dropped: u64,
    pub passed: u64,
    pub tx: u64,
    pub redirected: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for SkGlobalStats {}

#[cfg(feature = "userspace")]
pub struct SkGlobalStatsMap;

#[cfg(feature = "userspace")]
impl SkGlobalStatsMap {
    pub fn get(bpf: &mut Ebpf) -> Result<PerCpuArray<MapData, SkGlobalStats>, VanguardError> {
        get_map!(bpf, "SK_STATS", PerCpuArray, PerCpuArray<MapData, SkGlobalStats>)
    }

    pub fn get_total(bpf: &mut Ebpf) -> Result<SkGlobalStats, VanguardError> {
        let stats_map = Self::get(bpf)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        
        let per_cpu_values = stats_map.get(&0, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        let mut total_stats = SkGlobalStats {
            total: 0,
            dropped: 0,
            passed: 0,
            tx: 0,
            redirected: 0,
        };

        for cpu_stat in per_cpu_values.iter() {
            total_stats.total += cpu_stat.total;
            total_stats.dropped += cpu_stat.dropped;
            total_stats.passed += cpu_stat.passed;
            total_stats.tx += cpu_stat.tx;
            total_stats.redirected += cpu_stat.redirected;
        }

        Ok(total_stats)
    }
}