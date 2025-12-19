mod vmd;
fn main() {
    println!("Hello, world!");

    let detector = vmd::VirtualMachineDetector::new();
    let is_vm = detector.is_virtual_machine();
    println!("--------------------------------");
    println!("Is Virtual Machine: {}", is_vm);
}
