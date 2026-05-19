import { Button } from "../common/button/Button";
import { Input } from "../common/input/Input";
import Styles from "./LoginForm.module.sass";

export function LoginForm() {
	return (
		<section className={Styles.panel}>
			<div className={Styles.form}>
				<Input
					htmlFor="username"
					inputId="username"
					type="text"
					labelContent="Username"
				/>

				<Input
					htmlFor="password"
					inputId="password"
					type="password"
					labelContent="Password"
				/>

				<p className={Styles.error}>Invalid username or password</p>

				<Button name="Login" buttonType="primary" />
				<Button name="Reset Password" buttonType="secondary" />
			</div>
		</section>
	);
}
