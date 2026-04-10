import { useMemo } from "react";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import DnsActionsBar from "../components/dns/DnsActionsBar";
import DnsHeader from "../components/dns/DnsHeader";
import DnsTabs from "../components/dns/DnsTabs";
import DnsValidationErrors from "../components/dns/DnsValidationErrors";
import GeneralTab from "../components/dns/tabs/GeneralTab";
import BlocklistTab from "../components/dns/tabs/BlocklistTab";
import DnsTunnelingTab from "../components/dns/tabs/DnsTunnelingTab";
import DnssecTab from "../components/dns/tabs/DnssecTab";
import { validateDnsInspectionConfig } from "../components/dns/validation";
import {
  applyDnsInspectionDraft,
  resetDnsInspectionAll,
  resetDnsInspectionTab,
  setBlocklistConfig,
  setBlocklistDomains,
  setDnsInspectionActiveTab,
  setDnssecCacheConfig,
  setDnssecCacheTtlConfig,
  setDnssecConfig,
  setDnssecPrimaryResolver,
  setDnssecResolverConfig,
  setDnssecSecondaryResolver,
  setDnsTunnelingConfig,
  setDnsTunnelingIgnoreDomains,
  setGeneralConfig,
} from "../features/dnsInspectionSlice";

export default function Dns() {
  const dispatch = useAppDispatch();
  const dnsState = useAppSelector((state) => state.dnsInspection);

  const errors = useMemo(
    () => validateDnsInspectionConfig(dnsState.draftConfig),
    [dnsState.draftConfig],
  );

  const hasChanges = useMemo(
    () =>
      JSON.stringify(dnsState.draftConfig) !==
      JSON.stringify(dnsState.appliedConfig),
    [dnsState.draftConfig, dnsState.appliedConfig],
  );

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <Navbar />

      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── DNS INSPECTION ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <DnsHeader
            enabled={dnsState.draftConfig.general.enabled}
            hasChanges={hasChanges}
          />

          <div className="bg-[#161616] border border-[#262626] mb-6">
            <DnsTabs
              activeTab={dnsState.activeTab}
              onTabChange={(tab) => dispatch(setDnsInspectionActiveTab(tab))}
            />

            <motion.div
              key={dnsState.activeTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-6"
            >
              {dnsState.activeTab === "general" && (
                <GeneralTab
                  config={dnsState.draftConfig.general}
                  onEnabledChange={(enabled) =>
                    dispatch(setGeneralConfig({ enabled }))
                  }
                />
              )}

              {dnsState.activeTab === "blocklist" && (
                <BlocklistTab
                  config={dnsState.draftConfig.blocklist}
                  onEnabledChange={(enabled) =>
                    dispatch(setBlocklistConfig({ enabled }))
                  }
                  onDomainsChange={(domains) =>
                    dispatch(setBlocklistDomains(domains))
                  }
                />
              )}

              {dnsState.activeTab === "dnsTunneling" && (
                <DnsTunnelingTab
                  config={dnsState.draftConfig.dnsTunneling}
                  onConfigChange={(partial) =>
                    dispatch(setDnsTunnelingConfig(partial))
                  }
                  onIgnoreDomainsChange={(domains) =>
                    dispatch(setDnsTunnelingIgnoreDomains(domains))
                  }
                />
              )}

              {dnsState.activeTab === "dnssec" && (
                <DnssecTab
                  config={dnsState.draftConfig.dnssec}
                  onConfigChange={(partial) =>
                    dispatch(setDnssecConfig(partial))
                  }
                  onResolverChange={(partial) =>
                    dispatch(setDnssecResolverConfig(partial))
                  }
                  onPrimaryResolverChange={(partial) =>
                    dispatch(setDnssecPrimaryResolver(partial))
                  }
                  onSecondaryResolverChange={(partial) =>
                    dispatch(setDnssecSecondaryResolver(partial))
                  }
                  onCacheChange={(partial) =>
                    dispatch(setDnssecCacheConfig(partial))
                  }
                  onCacheTtlChange={(partial) =>
                    dispatch(setDnssecCacheTtlConfig(partial))
                  }
                />
              )}
            </motion.div>
          </div>

          <DnsValidationErrors errors={errors} />

          <DnsActionsBar
            canApply={hasChanges && errors.length === 0}
            onApply={() => dispatch(applyDnsInspectionDraft())}
            onResetTab={() => dispatch(resetDnsInspectionTab())}
            onResetAll={() => dispatch(resetDnsInspectionAll())}
          />

          <div className="text-center text-xs text-[#4a4a4a]">
            DNS inspection module
            <span className="text-[#06b6d4] mx-3">|</span>
            Local config editor
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}
