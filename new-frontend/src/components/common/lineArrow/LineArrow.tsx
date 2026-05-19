import Style from "./LineArrow.module.sass";

type LineArrowProps = {
	className?: string;
	width?: number;
	height?: number;
};

export function LineArrow({
	className = `${Style.container}`,
	width = 320,
	height = 16,
}: LineArrowProps) {
	return (
		<div className={`${Style.container}`}>
			<svg
				className={className}
				width={width}
				height={height}
				viewBox="0 0 320 16"
				fill="none"
				xmlns="http://www.w3.org/2000/svg"
				aria-hidden="true"
			>
				<path
					d="M20 8H300"
					stroke="currentColor"
					strokeWidth="1"
					strokeLinecap="square"
					shapeRendering="crispEdges"
				/>
				<path d="M6 8L20 2V14L6 8Z" fill="currentColor" />
				<path d="M314 8L300 2V14L314 8Z" fill="currentColor" />
			</svg>
		</div>
	);
}
