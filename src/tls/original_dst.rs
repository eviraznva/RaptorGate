use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use tokio::net::TcpStream;

const SOL_IP: libc::c_int = 0;
const SO_ORIGINAL_DST: libc::c_int = 80;
const SOL_IPV6: libc::c_int = 41;
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

// Odczytuje oryginalny adres docelowy z gniazda przekierowanego przez iptables TPROXY/REDIRECT.
pub fn get_original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();

    if let Ok(addr) = get_original_dst_v4(fd) {
        return Ok(addr);
    }

    get_original_dst_v6(fd)
}

fn get_original_dst_v4(fd: libc::c_int) -> io::Result<SocketAddr> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(ip.into(), port))
}

fn get_original_dst_v6(fd: libc::c_int) -> io::Result<SocketAddr> {
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    Ok(SocketAddr::new(ip.into(), port))
}
