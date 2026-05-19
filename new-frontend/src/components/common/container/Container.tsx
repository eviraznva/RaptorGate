import type { ReactNode } from "react";
import Style from "./Containter.module.sass";

interface ContainerProps {
	children: ReactNode;
	className?: string;
}

export function Container({ children, className }: ContainerProps) {
	return (
		<section className={`${Style.container} ${className || ""}`}>
			{children}
		</section>
	);
}
