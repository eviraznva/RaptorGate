import { useCallback, useEffect, useMemo, useState } from "react";
import UsersDeleteModal from "./UsersDeleteModal";
import UsersDetailsPanel from "./UsersDetailsPanel";
import UsersFooter from "./UsersFooter";
import UsersFormDrawer from "./UsersFormDrawer";
import UsersListMetaBar from "./UsersListMetaBar";
import UsersPageHeader from "./UsersPageHeader";
import UsersTable from "./UsersTable";
import UsersToolbar, { type UsersFilter } from "./UsersToolbar";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import {
  useCreateUserMutation,
  useDeleteUserMutation,
  useGetUsersQuery,
  useUpdateUserMutation,
  type CreateUserBody,
  type UsersPayload,
} from "../../services/users";
import type { ApiFailure, ApiSuccess } from "../../types/ApiResponse";
import {
  addUser,
  editUser,
  setUsers,
} from "../../features/usersManagementSlice";
import { deleteUser as deleteUserReducer } from "../../features/usersManagementSlice";

import type { DashboardUser } from "../../types/users/User";
import { StateError } from "./UsersStatesPanel";

type DrawerMode = "create" | "edit" | null;

export default function UsersModule() {
  const dispatch = useAppDispatch();
  const usersState = useAppSelector((state) => state.usersManagement);
  const [responseError, setResponseError] = useState<ApiFailure>();

  const { data: usersData } = useGetUsersQuery();

  const [createUser, { isError: isCreatingUserError }] =
    useCreateUserMutation();
  const [updateUser, { isError: isUpdateingUserError }] =
    useUpdateUserMutation();
  const [deleteUser, { isError: isDeletingUserError }] =
    useDeleteUserMutation();

  const [activeFilter, setActiveFilter] = useState<UsersFilter>("all");
  const [selectedUserId, setSelectedUserId] = useState<string | null>(
    usersState.users[0]?.id ?? null,
  );
  const [drawerMode, setDrawerMode] = useState<DrawerMode>(null);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [deleteUserId, setDeleteUserId] = useState<string | null>(null);

  useEffect(() => {
    if (!usersData) return;

    const payload = usersData as ApiSuccess<UsersPayload>;

    dispatch(setUsers(payload.data.users));
  }, [usersData, dispatch]);

  const selectedUser = useMemo(
    () => usersState.users.find((user) => user.id === selectedUserId) ?? null,
    [selectedUserId, usersState.users],
  );

  const editingUser = useMemo(
    () => usersState.users.find((user) => user.id === editingUserId) ?? null,
    [editingUserId, usersState.users],
  );

  const handleCreateUser = async function (userData: CreateUserBody) {
    try {
      const response = await createUser(userData).unwrap();

      if (response.statusCode === 201) {
        const payload = response as ApiSuccess<{ user: DashboardUser }>;
        return payload.data.user;
      }
    } catch (error) {
      setResponseError(error as ApiFailure);
    }
  };

  const handleUpdateUser = async function (
    userData: Partial<CreateUserBody> & { id: string },
  ) {
    try {
      const response = await updateUser(userData).unwrap();

      if (response.statusCode === 200) {
        const payload = response as ApiSuccess<{ user: DashboardUser }>;
        return payload.data.user;
      }
    } catch (error) {
      setResponseError(error as ApiFailure);
    }
  };

  const handleCreate = useCallback(() => {
    setEditingUserId(null);
    setDrawerMode("create");
  }, []);

  const handleEdit = useCallback((id: string) => {
    setSelectedUserId(id);
    setEditingUserId(id);
    setDrawerMode("edit");
  }, []);

  const handleDelete = useCallback((id: string) => {
    setDeleteUserId(id);
  }, []);

  const handleCloseDrawer = useCallback(() => {
    setDrawerMode(null);
  }, []);

  const handleSaveDrawer = useCallback(
    async (user: CreateUserBody, mode: DrawerMode) => {
      if (mode === "create") {
        const createdUser = await handleCreateUser(user);

        if (createdUser === undefined) return;
        dispatch(addUser(createdUser));
      }

      if (mode === "edit" && editingUserId) {
        const updatedUser = await handleUpdateUser({
          id: editingUserId,
          ...{
            username: user.username === "" ? undefined : user.username,
            password: user.password === "" ? undefined : user.password,
            roles: user.roles.length === 0 ? undefined : user.roles,
          },
        });

        if (updatedUser === undefined) return;
        dispatch(editUser(updatedUser));
      }

      setDrawerMode(null);
    },
    [editingUserId, dispatch],
  );

  const handleCloseDeleteModal = useCallback(() => {
    setDeleteUserId(null);
  }, []);

  const handleConfirmDelete = useCallback(
    async (id: string) => {
      await deleteUser(id);

      if (!isDeletingUserError) dispatch(deleteUserReducer(id));

      setDeleteUserId(null);
    },
    [deleteUser, isDeletingUserError, dispatch],
  );

  return (
    <>
      <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
        <div className="flex-1 flex justify-center p-8">
          <div className="w-full max-w-[100rem]">
            <UsersPageHeader />
            <div className="bg-[#161616] border border-[#262626] mb-6">
              <UsersToolbar
                activeFilter={activeFilter}
                onFilterChange={setActiveFilter}
                onCreate={handleCreate}
              />

              <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.65fr)_340px] min-h-[620px]">
                <div className="min-w-0">
                  <UsersListMetaBar visibleCount={usersState.users.length} />
                  <UsersTable
                    users={usersState.users}
                    selectedId={selectedUserId}
                    onSelect={setSelectedUserId}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                  />
                </div>

                <UsersDetailsPanel user={selectedUser} />
              </div>

              {isCreatingUserError && (
                <StateError
                  error={responseError?.error}
                  message={responseError?.message}
                />
              )}

              {isUpdateingUserError && (
                <StateError
                  error={responseError?.error}
                  message={responseError?.message}
                />
              )}
            </div>

            <UsersFooter />
          </div>
        </div>
      </div>

      <UsersFormDrawer
        isOpen={drawerMode !== null}
        mode={drawerMode}
        user={editingUser}
        onClose={handleCloseDrawer}
        onSave={handleSaveDrawer}
      />

      <UsersDeleteModal
        isOpen={deleteUserId !== null}
        user={usersState.users.find((user) => user.id === deleteUserId) ?? null}
        onCancel={handleCloseDeleteModal}
        onConfirm={handleConfirmDelete}
      />
    </>
  );
}
