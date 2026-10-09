import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

export const DiodeCanvas3D: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    const scene = new THREE.Scene();
    // Light background scene
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 2, 16);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.9);
    scene.add(ambientLight);
    const pointLight = new THREE.PointLight(0xffffff, 0.4);
    pointLight.position.set(5, 10, 8);
    scene.add(pointLight);

    // Unidirectional Conduit Path (Monochrome)
    const pathLength = 14;
    const pathGeometry = new THREE.BoxGeometry(pathLength, 0.04, 0.04);
    const pathMaterial = new THREE.MeshBasicMaterial({ 
      color: 0xD4D4D4, 
      transparent: true, 
      opacity: 0.8 
    });
    const pathLine = new THREE.Mesh(pathGeometry, pathMaterial);
    scene.add(pathLine);

    // Guard Ring Markers
    const ringGeo = new THREE.TorusGeometry(0.5, 0.02, 16, 32);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0xCCCCCC });
    
    const ring1 = new THREE.Mesh(ringGeo, ringMat);
    ring1.position.x = -pathLength / 4;
    ring1.rotation.y = Math.PI / 2;
    scene.add(ring1);

    const ring2 = new THREE.Mesh(ringGeo, ringMat);
    ring2.position.x = pathLength / 4;
    ring2.rotation.y = Math.PI / 2;
    scene.add(ring2);

    // Source Node (Monochrome Box)
    const nodeGeo = new THREE.BoxGeometry(0.8, 0.8, 0.8);
    const nodeMat = new THREE.MeshStandardMaterial({ 
      color: 0x111111,
      roughness: 0.3,
      metalness: 0.1
    });

    const startNode = new THREE.Mesh(nodeGeo, nodeMat);
    startNode.position.x = -pathLength / 2;
    scene.add(startNode);

    // Destination Node (Hardware Diode Terminator)
    const endNode = new THREE.Mesh(nodeGeo, nodeMat);
    endNode.position.x = pathLength / 2;
    scene.add(endNode);

    // Particles (Unidirectional flow)
    const particleCount = 28;
    const particleGeo = new THREE.SphereGeometry(0.08, 12, 12);
    const particleMat = new THREE.MeshBasicMaterial({ color: 0x222222 });

    const particles: { mesh: THREE.Mesh; speed: number }[] = [];

    for (let i = 0; i < particleCount; i++) {
      const p = new THREE.Mesh(particleGeo, particleMat);
      p.position.x = (Math.random() - 0.5) * pathLength;
      p.position.y = (Math.random() - 0.5) * 0.1;
      p.position.z = (Math.random() - 0.5) * 0.1;
      const speed = 0.03 + Math.random() * 0.04;
      scene.add(p);
      particles.push({ mesh: p, speed });
    }

    let animationFrameId: number;

    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);

      // Unidirectional forward propagation ONLY (Strict Diode Model)
      particles.forEach(({ mesh, speed }) => {
        mesh.position.x += speed;
        if (mesh.position.x > pathLength / 2) {
          mesh.position.x = -pathLength / 2;
        }
      });

      startNode.rotation.y += 0.008;
      startNode.rotation.x += 0.004;
      endNode.rotation.y += 0.008;
      endNode.rotation.x += 0.004;

      ring1.rotation.z += 0.005;
      ring2.rotation.z -= 0.005;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
      if (container && renderer.domElement) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, []);

  return (
    <div className="relative w-full h-[220px] bg-white border border-border rounded overflow-hidden shadow-subtle flex items-center justify-center">
      <div ref={containerRef} className="w-full h-full" />
      
      {/* HUD Overlays */}
      <div className="absolute inset-0 pointer-events-none p-4 flex flex-col justify-between">
        <div className="flex justify-between items-center w-full">
          <div className="bg-white/90 backdrop-blur border border-border px-2.5 py-1 rounded text-[11px] font-mono text-primary flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-black"></span>
            <span>TAP: Protected Network Ingest</span>
          </div>
          <div className="bg-white/90 backdrop-blur border border-border px-2.5 py-1 rounded text-[11px] font-mono text-primary flex items-center gap-1.5">
            <span>ENGINE: UNIGUARD AI Sink</span>
            <span className="w-1.5 h-1.5 rounded-full bg-status-healthy"></span>
          </div>
        </div>

        <div className="self-center bg-[#FAFAF8]/95 px-3 py-1 border border-border rounded backdrop-blur text-[10px] uppercase font-mono tracking-widest text-secondary">
          Hardware Unidirectional Diode Simulation — Outbound Feedback Inhibited (0 Return Packets)
        </div>
      </div>
    </div>
  );
};
