import Style from "./Button.module.sass";

interface ButtonProps {
	name: string;
	className?: string;
	buttonType: "primary" | "secondary";
	type?: "button" | "submit" | "reset";
	disabled?: boolean;
}

export function Button({
	name,
	className,
	buttonType,
	type = "button",
	disabled,
}: ButtonProps) {
	return (
		<button
			type={type}
			disabled={disabled}
			className={`${className} ${Style.button} ${Style[buttonType]}`}
		>
			{name}
		</button>
	);
}
