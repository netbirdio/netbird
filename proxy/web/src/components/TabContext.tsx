import { createContext, useContext } from "react";

type TabContextValue = {
  value: string;
  onChange: (value: string) => void;
};

export const TabContext = createContext<TabContextValue>({
  value: "",
  onChange: () => {},
});

export const useTabContext = () => useContext(TabContext);