import { createContext, useState, useContext } from "react";

type AuthContextType = {
  isAuthenticated: boolean;
  login: (access: string) => void;
  logout: () => void;
};

// ✅ TU BYŁ BŁĄD — brak export
export const AuthContext = createContext<AuthContextType>(null!);

export const AuthProvider = ({ children }: any) => {
  const [isAuthenticated, setIsAuthenticated] = useState(
    !!localStorage.getItem("access_token")
  );

  const login = (access: string) => {
  localStorage.setItem("access_token", access);
  setIsAuthenticated(true);
};

  const logout = () => {
    localStorage.clear();
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// ✅ używaj tylko tego hooka
export const useAuth = () => useContext(AuthContext);