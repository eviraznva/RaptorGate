import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { login } from "#/lib/auth-api";
import { setAuth } from "#/lib/auth-store";
import { Button } from "../common/button/Button";
import { Input } from "../common/input/Input";
import Styles from "./LoginForm.module.sass";

export function LoginForm() {
	const navigate = useNavigate();
	const loginMutation = useMutation({
		mutationFn: login,
		onSuccess: (response) => {
			setAuth(response.data);
			navigate({ to: "/dashboard" });
		},
	});

	function handleSubmit(event: React.SubmitEvent<HTMLFormElement>) {
		event.preventDefault();

		const formData = new FormData(event.currentTarget);

		loginMutation.mutate({
			username: String(formData.get("username")),
			password: String(formData.get("password")),
		});
	}

	return (
		<section className={Styles.panel}>
			<form className={Styles.form} onSubmit={handleSubmit}>
				<Input
					htmlFor="username"
					inputId="username"
					name="username"
					type="text"
					autoComplete="username"
					required
					labelContent="Username"
				/>

				<Input
					htmlFor="password"
					inputId="password"
					name="password"
					type="password"
					autoComplete="current-password"
					required
					labelContent="Password"
				/>

				{loginMutation.isError && (
					<p className={Styles.error}>Invalid username or password</p>
				)}

				<Button
					name={loginMutation.isPending ? "Logging in..." : "Login"}
					buttonType="primary"
					type="submit"
					disabled={loginMutation.isPending}
				/>
				<Button name="Reset Password" buttonType="secondary" />
			</form>
		</section>
	);
}
