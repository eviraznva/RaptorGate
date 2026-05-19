import Style from "./Button.module.sass";

interface ButtonProps {
	name: string;
	className?: string;
	buttonType: "primary" | "secondary";
}

export function Button({ name, className, buttonType }: ButtonProps) {
	return (
		<button
			type="button"
			className={`${className} ${Style.button} ${Style[buttonType]}`}
		>
			{name}
		</button>
	);
}
