import { useMemo } from "react";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import IpsActionsBar from "../components/ips/IpsActionsBar";
import IpsHeader from "../components/ips/IpsHeader";
import IpsTabs from "../components/ips/IpsTabs";
import IpsValidationErrors from "../components/ips/IpsValidationErrors";
import DetectionTab from "../components/ips/tabs/DetectionTab";
import GeneralTab from "../components/ips/tabs/GeneralTab";
import SignaturesTab from "../components/ips/tabs/SignaturesTab";
import { validateIpsConfig } from "../components/ips/validation";
import {
  addIpsSignature,
  applyIpsDraft,
  removeIpsSignature,
  resetIpsAll,
  resetIpsTab,
  selectIpsSignature,
  setIpsActiveTab,
  setIpsDetectionConfig,
  setIpsGeneralConfig,
  setSelectedIpsSignatureDstPorts,
  setSelectedIpsSignatureProtocols,
  setSelectedIpsSignatureSrcPorts,
  updateSelectedIpsSignature,
} from "../features/ipsConfigSlice";

export default function Ips() {
  const dispatch = useAppDispatch();
  const ipsState = useAppSelector((state) => state.ipsConfig);

  const errors = useMemo(
    () => validateIpsConfig(ipsState.draftConfig),
    [ipsState.draftConfig],
  );

  const hasChanges = useMemo(
    () =>
      JSON.stringify(ipsState.draftConfig) !==
      JSON.stringify(ipsState.appliedConfig),
    [ipsState.draftConfig, ipsState.appliedConfig],
  );

  const selectedSignature = useMemo(
    () =>
      ipsState.draftConfig.signatures.find(
        (signature) => signature.id === ipsState.selectedSignatureId,
      ) ?? null,
    [ipsState.draftConfig.signatures, ipsState.selectedSignatureId],
  );

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <Navbar />

      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-6xl">
          <div className="flex items-center justify-center mb-10">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
            <span className="px-4 text-[#06b6d4] text-xs">
              ◄──────────── IPS CONFIGURATION ────────────►
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent" />
          </div>

          <IpsHeader
            enabled={ipsState.draftConfig.general.enabled}
            signatureCount={ipsState.draftConfig.signatures.length}
            hasChanges={hasChanges}
          />

          <div className="bg-[#161616] border border-[#262626] mb-6">
            <IpsTabs
              activeTab={ipsState.activeTab}
              onTabChange={(tab) => dispatch(setIpsActiveTab(tab))}
            />

            <motion.div
              key={ipsState.activeTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-6"
            >
              {ipsState.activeTab === "general" && (
                <GeneralTab
                  config={ipsState.draftConfig.general}
                  onEnabledChange={(enabled) =>
                    dispatch(setIpsGeneralConfig({ enabled }))
                  }
                />
              )}

              {ipsState.activeTab === "detection" && (
                <DetectionTab
                  config={ipsState.draftConfig.detection}
                  onConfigChange={(partial) =>
                    dispatch(setIpsDetectionConfig(partial))
                  }
                />
              )}

              {ipsState.activeTab === "signatures" && (
                <SignaturesTab
                  config={ipsState.draftConfig}
                  selectedSignatureId={ipsState.selectedSignatureId}
                  selectedSignature={selectedSignature}
                  onSelectSignature={(id) => dispatch(selectIpsSignature(id))}
                  onAddSignature={() => dispatch(addIpsSignature())}
                  onRemoveSignature={(id) => dispatch(removeIpsSignature(id))}
                  onUpdateSelectedSignature={(partial) =>
                    dispatch(updateSelectedIpsSignature(partial))
                  }
                  onUpdateProtocols={(protocols) =>
                    dispatch(setSelectedIpsSignatureProtocols(protocols))
                  }
                  onUpdateSrcPorts={(ports) =>
                    dispatch(setSelectedIpsSignatureSrcPorts(ports))
                  }
                  onUpdateDstPorts={(ports) =>
                    dispatch(setSelectedIpsSignatureDstPorts(ports))
                  }
                />
              )}
            </motion.div>
          </div>

          <IpsValidationErrors errors={errors} />

          <IpsActionsBar
            canApply={hasChanges && errors.length === 0}
            onApply={() => dispatch(applyIpsDraft())}
            onResetTab={() => dispatch(resetIpsTab())}
            onResetAll={() => dispatch(resetIpsAll())}
          />

          <div className="text-center text-xs text-[#4a4a4a]">
            IPS configuration module
            <span className="text-[#06b6d4] mx-3">|</span>
            Signature detection tuning
            <span className="text-[#06b6d4] mx-3">|</span>
            RaptorGate UI
          </div>
        </div>
      </div>
    </div>
  );
}
