import Styles from "./Input.module.sass";

interface InputProps {
	labelContent: string;
	inputId: string;
	htmlFor: string;
	type: string;
	name?: string;
	autoComplete?: string;
	required?: boolean;
	fieldClassName?: string;
	labelClassName?: string;
	inputClassName?: string;
}

export function Input({
	labelContent,
	inputId,
	htmlFor,
	type,
	name,
	autoComplete,
	required,
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
				name={name}
				type={type}
				autoComplete={autoComplete}
				required={required}
				className={`${Styles.input} ${inputClassName}`}
			/>
		</div>
	);
}
