import { useEffect, useState } from "react";

export const useWebSocket = (url: string) => {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    let ws = new WebSocket(url);

    ws.onmessage = (event) => {
      setData(JSON.parse(event.data));
    };

    ws.onclose = () => {
      setTimeout(() => {
        ws = new WebSocket(url);
      }, 2000);
    };

    return () => ws.close();
  }, [url]);

  return data;
};