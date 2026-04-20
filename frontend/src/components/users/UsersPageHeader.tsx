export default function UsersPageHeader() {
  return (
    <div className="text-center mb-8">
      <div className="text-[12px] tracking-[0.35em] text-[#4a4a4a] uppercase mb-2">
        Administrative Control Surface
      </div>
      <div className="flex items-center justify-center gap-3 mb-2">
        <span className="h-px w-20 bg-gradient-to-r from-transparent to-[#06b6d4]" />
        <span className="text-[15px] tracking-[0.3em] uppercase text-[#06b6d4]">User Management</span>
        <span className="h-px w-20 bg-gradient-to-l from-transparent to-[#06b6d4]" />
      </div>
      <div className="text-[12px] tracking-[0.25em] text-[#8a8a8a] uppercase">
        Dashboard Module For User Directory
      </div>
    </div>
  );
}
