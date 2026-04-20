import { useCallback, useEffect, useState } from "react";
import ZonesPageHeader from "../components/zones/ZonesPageHeader";
import ZonesStatusBar from "../components/zones/ZonesStatusBar";
import ZonesTabs, { type ZonesTabKey } from "../components/zones/ZonesTabs";
import ZonesTable from "../components/zones/ZonesTable";
import ZonePairsTable from "../components/zones/ZonePairsTable";
import ZoneForm from "../components/zones/ZoneForm";
import ZonePairForm from "../components/zones/ZonePairForm";
import ZonesFooter from "../components/zones/ZonesFooter";
import type { Zone } from "../types/zones/Zone";
import type { ZonePair } from "../types/zones/ZonePair";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import {
  useCreateZoneMutation,
  useDeleteZoneMutation,
  useGetZonesQuery,
  useUpdateZoneMutation,
  type CreateZoneBody,
  type ZonesPayload,
} from "../services/zones";
import {
  useCreateZonePairMutation,
  useDeleteZonePairMutation,
  useGetZonePairsQuery,
  useUpdateZonePairMutation,
  type CreateZonePairBody,
  type ZonePairsPayload,
} from "../services/zonePairs";
import * as zonesSliceReducers from "../features/zonesSlice";
import * as zonePairsSliceReducers from "../features/zonePairsSlice";
import type { ApiSuccess } from "../types/ApiResponse";

export default function Zones() {
  const dispatch = useAppDispatch();
  const zonesState = useAppSelector((state) => state.zones);
  const zonePairsState = useAppSelector((state) => state.zonePairs);

  const { data: zonesData } = useGetZonesQuery();
  const { data: zonePairsData } = useGetZonePairsQuery();

  const [createZone] = useCreateZoneMutation();
  const [updateZone] = useUpdateZoneMutation();
  const [deleteZone, { isError: isDeletingZoneError }] = useDeleteZoneMutation();

  const [createZonePair] = useCreateZonePairMutation();
  const [updateZonePair] = useUpdateZonePairMutation();
  const [deleteZonePair, { isError: isDeletingZonePairError }] = useDeleteZonePairMutation();

  useEffect(() => {
    if (!zonesData) return;
    const payload = zonesData as ApiSuccess<ZonesPayload>;
    dispatch(zonesSliceReducers.setZones(payload.data.zones));
  }, [zonesData, dispatch]);

  useEffect(() => {
    if (!zonePairsData) return;
    const payload = zonePairsData as ApiSuccess<ZonePairsPayload>;
    dispatch(zonePairsSliceReducers.setZonePairs(payload.data.zonePairs));
  }, [zonePairsData, dispatch]);

  const [activeTab, setActiveTab] = useState<ZonesTabKey>("zones");

  const [isZoneFormOpen, setIsZoneFormOpen] = useState(false);
  const [editingZone, setEditingZone] = useState<Zone | null>(null);
  const [confirmDeleteZoneId, setConfirmDeleteZoneId] = useState<string | null>(null);

  const [isZonePairFormOpen, setIsZonePairFormOpen] = useState(false);
  const [editingZonePair, setEditingZonePair] = useState<ZonePair | null>(null);
  const [confirmDeletePairId, setConfirmDeletePairId] = useState<string | null>(null);

  // ── Zone handlers ──
  const handleCreateZone = async function (data: CreateZoneBody) {
    try {
      const res = await createZone(data).unwrap();
      if (res.statusCode === 201) {
        const { data } = res as ApiSuccess<{ zone: Zone }>;
        return data.zone;
      }
    } catch (error) {}
  };

  const handleUpdateZone = async function (id: string, data: Partial<CreateZoneBody>) {
    try {
      const res = await updateZone({ id, ...data }).unwrap();
      if (res.statusCode === 200) {
        const { data } = res as ApiSuccess<{ zone: Zone }>;
        return data.zone;
      }
    } catch (error) {}
  };

  const handleDeleteZoneApi = async function (id: string) {
    try {
      const res = await deleteZone(id).unwrap();
      return res;
    } catch (error) {}
  };

  const handleNewZone = useCallback(() => {
    setEditingZone(null);
    setIsZoneFormOpen(true);
  }, []);

  const handleEditZone = useCallback((zone: Zone) => {
    setEditingZone(zone);
    setIsZoneFormOpen(true);
  }, []);

  const handleCloseZoneForm = useCallback(() => setIsZoneFormOpen(false), []);

  const handleZoneSuccess = useCallback(
    async (zone: Zone, mode: "create" | "edit") => {
      if (mode === "edit") {
        const updatedZone = await handleUpdateZone(zone.id, {
          name: zone.name,
          description: zone.description,
          isActive: zone.isActive,
        });

        if (updatedZone === undefined) return;
        dispatch(zonesSliceReducers.editZone(updatedZone));
      }

      if (mode === "create") {
        const newZone = await handleCreateZone({
          name: zone.name,
          description: zone.description,
          isActive: zone.isActive,
        });

        if (newZone === undefined) return;
        dispatch(zonesSliceReducers.addZone(newZone));
      }

      setIsZoneFormOpen(false);
    },
    [dispatch],
  );

  const handleZoneDeleteClick = useCallback((id: string) => setConfirmDeleteZoneId(id), []);
  const handleZoneDeleteCancel = useCallback(() => setConfirmDeleteZoneId(null), []);

  const handleZoneDeleteConfirm = useCallback(async (id: string) => {
    await handleDeleteZoneApi(id);
    if (!isDeletingZoneError) dispatch(zonesSliceReducers.deleteZone(id));
    setConfirmDeleteZoneId(null);
  }, [dispatch, isDeletingZoneError]);


  // ── Zone pair handlers ──
  const handleCreateZonePair = async function (data: CreateZonePairBody) {
    try {
      const res = await createZonePair(data).unwrap();
      if (res.statusCode === 201) {
        const { data } = res as ApiSuccess<{ zonePair: ZonePair }>;
        return data.zonePair;
      }
    } catch (error) {}
  };

  const handleUpdateZonePair = async function (id: string, data: Partial<CreateZonePairBody>) {
    try {
      const res = await updateZonePair({ id, ...data }).unwrap();
      if (res.statusCode === 200) {
        const { data } = res as ApiSuccess<{ zonePair: ZonePair }>;
        return data.zonePair;
      }
    } catch (error) {}
  };

  const handleDeleteZonePairApi = async function (id: string) {
    try {
      const res = await deleteZonePair(id).unwrap();
      return res;
    } catch (error) {}
  };

  const handleNewZonePair = useCallback(() => {
    setEditingZonePair(null);
    setIsZonePairFormOpen(true);
  }, []);

  const handleEditZonePair = useCallback((pair: ZonePair) => {
    setEditingZonePair(pair);
    setIsZonePairFormOpen(true);
  }, []);

  const handleCloseZonePairForm = useCallback(() => setIsZonePairFormOpen(false), []);

  const handleZonePairSuccess = useCallback(
    async (pair: ZonePair, mode: "create" | "edit") => {
      const payload: CreateZonePairBody = {
        srcZoneId: pair.srcZoneId,
        dstZoneId: pair.dstZoneId,
        defaultPolicy: pair.defaultPolicy,
      };

      if (mode === "edit") {
        const updatedPair = await handleUpdateZonePair(pair.id, payload);

        if (updatedPair === undefined) return;
        dispatch(zonePairsSliceReducers.editZonePair(updatedPair));
      }

      if (mode === "create") {
        const newPair = await handleCreateZonePair(payload);

        if (newPair === undefined) return;
        dispatch(zonePairsSliceReducers.addZonePair(newPair));
      }

      setIsZonePairFormOpen(false);
    },
    [dispatch],
  );

  const handlePairDeleteClick = useCallback((id: string) => setConfirmDeletePairId(id), []);
  const handlePairDeleteCancel = useCallback(() => setConfirmDeletePairId(null), []);

  const handlePairDeleteConfirm = useCallback(async (id: string) => {
    await handleDeleteZonePairApi(id);
    if (!isDeletingZonePairError) dispatch(zonePairsSliceReducers.deleteZonePair(id));
    setConfirmDeletePairId(null);
  }, [dispatch, isDeletingZonePairError]);

  return (
    <>
      <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
        <div className="flex-1 flex justify-center p-8">
          <div className="w-full max-w-7xl">
            <ZonesPageHeader />
            <ZonesStatusBar
              activeTab={activeTab}
              zones={zonesState.zones}
              zonePairs={zonePairsState.zonePairs}
            />
            <div className="bg-[#161616] border border-[#262626] mb-6">
              <ZonesTabs activeTab={activeTab} onTabChange={setActiveTab} />
              <div key={activeTab} className="p-6">
                {activeTab === "zones" && (
                  <ZonesTable
                    zones={zonesState.zones}
                    confirmDeleteId={confirmDeleteZoneId}
                    onNew={handleNewZone}
                    onEdit={handleEditZone}
                    onDeleteClick={handleZoneDeleteClick}
                    onDeleteConfirm={handleZoneDeleteConfirm}
                    onDeleteCancel={handleZoneDeleteCancel}
                  />
                )}
                {activeTab === "zone-pairs" && (
                  <ZonePairsTable
                    zonePairs={zonePairsState.zonePairs}
                    zones={zonesState.zones}
                    confirmDeleteId={confirmDeletePairId}
                    onNew={handleNewZonePair}
                    onEdit={handleEditZonePair}
                    onDeleteClick={handlePairDeleteClick}
                    onDeleteConfirm={handlePairDeleteConfirm}
                    onDeleteCancel={handlePairDeleteCancel}
                  />
                )}
              </div>
            </div>
            <ZonesFooter />
          </div>
        </div>
      </div>

      <ZoneForm
        zone={editingZone}
        isOpen={isZoneFormOpen}
        onClose={handleCloseZoneForm}
        onSuccess={handleZoneSuccess}
      />
      <ZonePairForm
        zonePair={editingZonePair}
        isOpen={isZonePairFormOpen}
        zones={zonesState.zones}
        onClose={handleCloseZonePairForm}
        onSuccess={handleZonePairSuccess}
      />
    </>
  );
}
