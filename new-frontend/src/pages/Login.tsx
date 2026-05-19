import { Container } from "#/components/common/container/Container";
import { LoginForm } from "#/components/loginForm/LoginForm";
import { LoginHeader } from "#/components/loginHeader/LoginHeader";

export function Login() {
	return (
		<Container>
			<LoginHeader />
			<LoginForm />
		</Container>
	);
}
