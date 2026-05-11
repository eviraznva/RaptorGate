// Logout per source IP (klucz runtime store, ADR 0003). Klient nie podaje
// session id — kontroler bierze sourceIp z req.ip.
export class LogoutIdentityDto {
  sourceIp: string;
}
