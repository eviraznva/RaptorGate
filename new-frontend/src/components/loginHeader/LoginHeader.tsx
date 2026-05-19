import { LineArrow } from "../common/lineArrow/LineArrow";
import Styles from "./LoginHeader.module.sass";

export function LoginHeader() {
	return (
		<header className={Styles.header}>
			<div className={Styles.flowLineWithArrow}>
				<div className={Styles.gradientLine} />
				<LineArrow width={250} className={Styles.arrow} />
				<div className={Styles.gradientLine} />
			</div>

			<div className={Styles.logo}>
				<h1 className={Styles.title}>RAPTORGATE</h1>
				<p className={Styles.subtitle}>Next-Generation Firewall</p>
			</div>

			<div className={Styles.flowLine}>
				<div className={Styles.gradientLine} />
			</div>
		</header>
	);
}
