#[cfg(feature = "userspace")]
use super::common::*;

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[cfg(feature = "userspace")]
use crate::error::VanguardError;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpGlobalStats {
    pub total: u64,
    pub dropped: u64,
    pub passed: u64,
    pub tx: u64,
    pub redirected: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpGlobalStats {}

#[cfg(feature = "userspace")]
pub struct GlobalStatsMap;

#[cfg(feature = "userspace")]
impl GlobalStatsMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<PerCpuArray<MapData, XdpGlobalStats>> {
        get_map!(bpf, "STATS", PerCpuArray, PerCpuArray<MapData, XdpGlobalStats>)
    }

    pub fn get_total(bpf: &mut Ebpf) -> ErrResult<XdpGlobalStats> {
        let stats_map = Self::get(bpf)
            .map_err(|e| VanguardError::EbpfMap(format!("Failed to get STATS map: {:?}", e)))?;
        
        let per_cpu_values = stats_map.get(&0, 0)?; 

        let mut total_stats = XdpGlobalStats {
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