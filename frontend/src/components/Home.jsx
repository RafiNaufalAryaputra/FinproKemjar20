import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import API from '../api/api';

const Home = () => {
    const userId = localStorage.getItem('userId');
    const [todos, setTodos] = useState([]);
    const [task, setTask] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [currentPassword, setCurrentPassword] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        fetchTodos();
    }, []);

    const fetchTodos = async () => {
        const response = await API.get(`/todos/${userId}`);
        setTodos(response.data);
    };

    const addTodo = async () => {
        await API.post('/todos', { userId, content: task });
        setTask('');
        fetchTodos();
    };

    const deleteTodo = async (id) => {
        await API.delete(`/todos/${id}`);
        fetchTodos();
    };

    const changePassword = async () => {
        try {
            await API.post('/change-password', { userId, currentPassword, newPassword });
            alert('Password changed successfully');
            setNewPassword('');
            setCurrentPassword('');
        } catch (err) {
            alert(err.response?.data?.message || 'Password change failed');
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('userId');
        navigate('/');
    };

    return (
        <div className="app-shell">
            <div className="container">
                <div className="sidebar">
                    <div className="logo">To Do List Mpruyyy</div>
                    <div className="subtitle">Tugas Izin</div>
                    <div style={{marginTop:20}}>
                        <button className="button secondary" onClick={handleLogout}>Logout</button>
                    </div>
                </div>
                <div className="main">
                    <h2 className="header">My Tasks</h2>
                    <div className="taskRow">
                        <input className="input" placeholder="New task..." value={task} onChange={(e)=>setTask(e.target.value)} />
                        <button className="button" onClick={addTodo}>Add Task</button>
                    </div>

                    <ul className="todoList" style={{marginTop:18}}>
                        {todos.map((entry) => (
                            <li key={entry.id} className="todoItem">
                                <div className="todoLeft">
                                    <div className="checkbox" />
                                    <div className="taskText">{entry.content}</div>
                                </div>
                                <div className="spaced">
                                    <button className="button" onClick={() => deleteTodo(entry.id)}>Delete</button>
                                </div>
                            </li>
                        ))}
                    </ul>

                    <div style={{marginTop:18}}>
                        <input className="input" type="password" placeholder="Current Password" value={currentPassword} onChange={(e)=>setCurrentPassword(e.target.value)} />
                        <input className="input" type="password" placeholder="New Password" value={newPassword} onChange={(e)=>setNewPassword(e.target.value)} />
                        <div style={{marginTop:8}}>
                            <button className="button" onClick={changePassword}>Change Password</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Home;
