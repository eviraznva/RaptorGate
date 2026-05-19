import Styles from "./Input.module.sass";

interface InputProps {
	labelContent: string;
	inputId: string;
	htmlFor: string;
	type: string;
	fieldClassName?: string;
	labelClassName?: string;
	inputClassName?: string;
}

export function Input({
	labelContent,
	inputId,
	htmlFor,
	type,
	fieldClassName,
	labelClassName,
	inputClassName,
}: InputProps) {
	return (
		<div className={`${Styles.field} ${fieldClassName}`}>
			<label className={`${Styles.label} ${labelClassName}`} htmlFor={htmlFor}>
				{labelContent}
			</label>

			<input
				id={inputId}
				type={type}
				className={`${Styles.input} ${inputClassName}`}
			/>
		</div>
	);
}
